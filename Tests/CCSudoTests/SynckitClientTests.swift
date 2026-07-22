@testable import CCSudo
import DaemonKit
import Foundation
import Testing

private final class OneShotServer: @unchecked Sendable {
    struct Request {
        let operation: String
        let payload: Data
    }

    private final class Capture: @unchecked Sendable {
        private let lock = NSLock()
        private var request: Request?
        private let done = DispatchSemaphore(value: 0)

        func record(_ request: Request) {
            lock.withLock { self.request = request }
            done.signal()
        }

        func value() throws -> Request {
            try #require(done.wait(timeout: .now() + 5) == .success)
            return try #require(lock.withLock { request })
        }
    }

    let path: String
    private let directory: URL
    private let server: SocketServer
    private let capture: Capture
    private let closeLock = NSLock()
    private var closed = false

    init(reply: String) throws {
        directory = FileManager.default.temporaryDirectory
            .appending(component: "ck-\(UInt32.random(in: 0 ..< UInt32.max))", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        path = directory.appending(component: "s.sock").path()
        let response = Data(reply.utf8)
        let capture = Capture()
        self.capture = capture
        server = SocketServer(
            path: path,
            build: SynckitClient.build,
            configuration: .init(maximumFrameBytes: SynckitClient.maximumFrameBytes),
            trust: .sameEffectiveUser
        ) { request in
            capture.record(Request(operation: request.operation, payload: request.payload))
            return .terminal(SocketTerminal(payload: response))
        }
        try server.start()
    }

    func request() throws -> Request {
        try capture.value()
    }

    func close() async {
        guard markClosed() else { return }
        let server = server
        let directory = directory
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                Self.settle(server: server, directory: directory)
                continuation.resume()
            }
        }
    }

    deinit {
        guard markClosed() else { return }
        let server = server
        let directory = directory
        DispatchQueue.global(qos: .userInitiated).async {
            Self.settle(server: server, directory: directory)
        }
    }

    private func markClosed() -> Bool {
        closeLock.withLock {
            guard !closed else { return false }
            closed = true
            return true
        }
    }

    private static func settle(server: SocketServer, directory: URL) {
        server.stop()
        try? FileManager.default.removeItem(at: directory)
    }
}

private func withOneShotServer<Result>(
    reply: String,
    body: (SynckitClient, OneShotServer) async throws -> Result
) async throws -> Result {
    let server = try OneShotServer(reply: reply)
    let client = SynckitClient(socketPath: server.path, deadline: 30)
    do {
        let result = try await body(client, server)
        client.close()
        await server.close()
        return result
    } catch {
        client.close()
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

        let request = try server.request()
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

@Test func missingSocketIsUnavailableUpstream() async throws {
    let client = SynckitClient(socketPath: "/nonexistent/rpc.sock", deadline: 1)
    defer { client.close() }
    let source = SynckitConsentSource(
        client: client,
        selfIdentity: "laptop"
    )
    do {
        _ = try await source.obtainSignature(ConsentRequest(argv: ["ls"], nonce: Data(repeating: 1, count: 24)))
        Issue.record("expected unavailable")
    } catch let error as ConsentError {
        guard case .unavailable = error else {
            Issue.record("want unavailable, got \(error)")
            return
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
    let bridge = SynckitBridgeClient(socketPath: "/Users/alice/.config/synckit/rpc.sock", userID: 501, runner: runner)

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
