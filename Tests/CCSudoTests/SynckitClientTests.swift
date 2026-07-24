@testable import CCSudo
@testable import DaemonKit
import Foundation
import Testing

private final class OneShotServer: @unchecked Sendable {
    private enum RequestWaitError: Error {
        case timedOut
    }

    struct Request: Sendable {
        let operation: String
        let payload: Data
    }

    private actor Capture {
        private var request: Request?
        private var waiters: [CheckedContinuation<Request, Never>] = []

        func record(_ request: Request) {
            self.request = request
            let pending = waiters
            waiters.removeAll()
            for waiter in pending {
                waiter.resume(returning: request)
            }
        }

        func value() async -> Request {
            if let request {
                return request
            }
            return await withCheckedContinuation { waiters.append($0) }
        }
    }

    let path: String
    private let directory: URL
    private let server: SocketServer
    private let capture: Capture

    init(reply: String) async throws {
        directory = FileManager.default.temporaryDirectory
            .appending(component: "ck-\(UInt32.random(in: 0 ..< UInt32.max))", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        path = directory.appending(component: "s.sock").path()
        let response = Data(reply.utf8)
        let capture = Capture()
        self.capture = capture
        var configuration = SocketServer.Configuration(
            maximumFrameBytes: SynckitClient.maximumFrameBytes
        )
        configuration.maximumSessions = 1
        server = SocketServer(
            path: path,
            wireBuild: SynckitClient.wireBuild,
            configuration: configuration
        ) { request in
            await capture.record(Request(operation: request.operation, payload: request.payload))
            return .terminal(SocketTerminal(payload: response))
        }
        try await server.start()
    }

    func request() async throws -> Request {
        try await withThrowingTaskGroup(of: Request.self) { group in
            group.addTask { await self.capture.value() }
            group.addTask {
                try await Task.sleep(for: .seconds(5))
                throw RequestWaitError.timedOut
            }
            let request = try await #require(group.next())
            group.cancelAll()
            return request
        }
    }

    func close() async {
        await server.stop()
        try? FileManager.default.removeItem(at: directory)
    }
}

private func withSynckitClient<Result>(
    _ client: SynckitClient,
    body: (SynckitClient) async throws -> Result
) async throws -> Result {
    do {
        let result = try await body(client)
        await client.close()
        return result
    } catch {
        await client.close()
        throw error
    }
}

private func withOneShotServer<Result>(
    reply: String,
    body: (SynckitClient, OneShotServer) async throws -> Result
) async throws -> Result {
    let server = try await OneShotServer(reply: reply)
    let client = SynckitClient(socketPath: server.path, deadline: 30)
    do {
        let result = try await body(client, server)
        await client.close()
        await server.close()
        return result
    } catch {
        await client.close()
        await server.close()
        throw error
    }
}

private let params = SynckitConsentParams(
    client: "cc-sudo",
    reason: "Run: dscacheutil -flushcache",
    subject: "sha256:abc",
    argv: ["dscacheutil", "-flushcache"],
    nonce: Data((0 ..< 24).map { UInt8($0) }).base64EncodedString(),
    ttlMS: 0,
    localOnly: false
)

@Suite(.serialized)
struct SynckitClientTests {
    @Test func consentRequestUsesExactPersistentWireShape() async throws {
        try await withOneShotServer(reply: """
        {"ok":true,"result":{"verdict":"approved","approved_by":"studio","routed":true,"cached":false,\
        "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"studio"}}}
        """) { client, server in
            let result = try await client.requestConsent(params)

            #expect(result.verdict == "approved")
            #expect(result.routed == true)
            let attestation = try #require(result.attestation)
            #expect(attestation.keyID == "kid")
            #expect(attestation.sig == "c2ln")
            #expect(attestation.signedBy == "studio")

            let request = try await server.request()
            #expect(request.operation == SynckitClient.operation)
            let sent = try JSONSerialization.jsonObject(with: request.payload) as? [String: Any]
            #expect(sent?["method"] as? String == "consent.request")
            let sentParams = try #require(sent?["params"] as? [String: Any])
            #expect(sentParams["client"] as? String == "cc-sudo")
            #expect(sentParams["argv"] as? [String] == ["dscacheutil", "-flushcache"])
            #expect(sentParams["ttl_ms"] as? Int == 0)
            #expect(sentParams["local_only"] as? Bool == false)
            #expect(sentParams["nonce"] as? String == params.nonce)
        }
    }

    @Test func rpcErrorsThrow() async throws {
        _ = try await withOneShotServer(reply: #"{"ok":false,"error":"prompt gate wedged"}"#) { client, _ in
            await #expect(throws: SynckitClient.ClientError.self) {
                _ = try await client.requestConsent(params)
            }
        }
    }

    @Test func concurrentRequestsCoalesceConnectionSetup() async throws {
        try await withOneShotServer(reply: #"{"ok":true,"result":{"verdict":"approved"}}"#) { client, _ in
            async let first = client.requestConsent(params)
            async let second = client.requestConsent(params)
            let firstResult = try await first
            let secondResult = try await second
            #expect(firstResult.verdict == "approved")
            #expect(secondResult.verdict == "approved")
        }
    }

    @Test func missingSocketIsUnavailableUpstream() async throws {
        let client = SynckitClient(socketPath: "/nonexistent/rpc.sock", deadline: 1)
        try await withSynckitClient(client) { client in
            let source = SynckitConsentSource(
                client: client,
                selfIdentity: "laptop"
            )
            do {
                _ = try await source.obtainSignature(
                    ConsentRequest(argv: ["ls"], nonce: Data(repeating: 1, count: 24))
                )
                Issue.record("expected unavailable")
            } catch let error as ConsentError {
                guard case .unavailable = error else {
                    Issue.record("want unavailable, got \(error)")
                    return
                }
            }
        }
    }

    // MARK: - SynckitConsentSource verdict mapping over the real socket

    private func consent(reply: String, selfIdentity: String = "laptop") async throws -> SignedConsent {
        try await withOneShotServer(reply: reply) { client, _ in
            let source = SynckitConsentSource(
                client: client,
                selfIdentity: selfIdentity
            )
            return try await source.obtainSignature(
                ConsentRequest(argv: ["dscacheutil", "-flushcache"], nonce: Data(repeating: 2, count: 24))
            )
        }
    }

    @Test func routedApprovalMapsToThePeerOrigin() async throws {
        let signed = try await consent(reply: """
        {"ok":true,"result":{"verdict":"approved","routed":true,\
        "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"studio"}}}
        """)
        #expect(signed.origin == .peer(host: "studio"))
        #expect(signed.signature == Data("sig".utf8))
    }

    @Test func selfSignedApprovalMapsToTheLocalOrigin() async throws {
        let signed = try await consent(reply: """
        {"ok":true,"result":{"verdict":"approved","routed":false,\
        "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"laptop"}}}
        """)
        #expect(signed.origin == .local)
    }

    @Test func approvalWithoutAttestationIsAProtocolViolation() async throws {
        await #expect(throws: ConsentError.self) {
            _ = try await consent(reply: #"{"ok":true,"result":{"verdict":"approved","routed":false}}"#)
        }
    }

    @Test func deniedVerdictIsTerminal() async throws {
        await #expect(throws: ConsentError.denied) {
            _ = try await consent(reply: #"{"ok":true,"result":{"verdict":"denied"}}"#)
        }
    }

    @Test func unavailableVerdictThrowsUnavailable() async throws {
        do {
            _ = try await consent(reply: #"{"ok":true,"result":{"verdict":"unavailable"}}"#)
            Issue.record("expected unavailable")
        } catch let error as ConsentError {
            guard case .unavailable = error else {
                Issue.record("want unavailable, got \(error)")
                return
            }
        }
    }

    @Test func unknownVerdictIsFatal() async throws {
        await #expect(throws: ConsentError.self) {
            _ = try await consent(reply: #"{"ok":true,"result":{"verdict":"maybe"}}"#)
        }
    }

    @Test func rootBridgeRunsThePinnedVerifierAsTheSocketOwner() async throws {
        let runner = FakeRunner { _, _ in
            .exit(0, stdout: """
            {"verdict":"approved","routed":true,
            "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"studio"}}
            """)
        }
        let bridge = SynckitBridgeClient(
            socketPath: "/Users/alice/.config/synckit/rpc.sock",
            userID: 501,
            runner: runner
        )

        let result = try await bridge.requestConsent(params)

        #expect(result.verdict == "approved")
        let spawn = try #require(runner.spawns.first)
        #expect(spawn.executable == "/usr/bin/sudo")
        #expect(spawn.arguments == [
            "-u", "#501", "-H", RunClient.verifierPath,
            "synckit-bridge", "--socket", "/Users/alice/.config/synckit/rpc.sock",
        ])
        let bridged = try JSONDecoder().decode(SynckitConsentParams.self, from: #require(spawn.stdin))
        #expect(bridged.client == params.client)
        #expect(bridged.argv == params.argv)
        #expect(bridged.nonce == params.nonce)
    }

    @Test func bridgeTransportFailureIsUnavailable() async throws {
        let runner = FakeRunner { _, _ in .exit(2, stderr: "connect failed") }
        let bridge = SynckitBridgeClient(socketPath: "/tmp/missing.sock", userID: 501, runner: runner)

        await #expect(throws: SynckitClient.ClientError.self) {
            _ = try await bridge.requestConsent(params)
        }
    }
}
