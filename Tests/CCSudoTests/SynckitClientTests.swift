@testable import CCSudo
import Foundation
import Testing

private enum SynckitFixtureError: Error, CustomStringConvertible {
    case binaryMissing
    case mkdtemp(Int32)
    case exited
    case timedOut
    case malformedLine(String)

    var description: String {
        switch self {
        case .binaryMissing:
            "CC_SUDO_SYNCKIT_FIXTURE is unset; run scripts/swift-test.sh"
        case let .mkdtemp(code):
            "mkdtemp failed with errno \(code)"
        case .exited:
            "synckit fixture closed its output"
        case .timedOut:
            "synckit fixture printed no line in time"
        case let .malformedLine(line):
            "unexpected synckit fixture line: \(line)"
        }
    }
}

private final class FixtureLines: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()
    private var lines: [String] = []
    private var finished = false

    init(_ handle: FileHandle) {
        handle.readabilityHandler = { [weak self] handle in
            self?.ingest(handle.availableData)
        }
    }

    private func ingest(_ chunk: Data) {
        lock.withLock {
            guard !chunk.isEmpty else {
                finished = true
                return
            }
            buffer.append(chunk)
            while let newline = buffer.firstIndex(of: UInt8(ascii: "\n")) {
                lines.append(String(bytes: buffer[buffer.startIndex ..< newline], encoding: .utf8) ?? "")
                buffer.removeSubrange(buffer.startIndex ... newline)
            }
        }
    }

    func next(timeout: Duration) async throws -> String {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while true {
            let (line, done) = lock.withLock { () -> (String?, Bool) in
                lines.isEmpty ? (nil, finished) : (lines.removeFirst(), false)
            }
            if let line {
                return line
            }
            if done {
                throw SynckitFixtureError.exited
            }
            guard ContinuousClock.now < deadline else {
                throw SynckitFixtureError.timedOut
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }
}

private final class SynckitFixture: @unchecked Sendable {
    struct Request: Sendable {
        let operation: String
        let payload: Data
    }

    let home: URL
    let socketPath: String
    private let process: Process
    private let stdin: Pipe
    private let lines: FixtureLines

    init(reply: String) async throws {
        guard let binary = ProcessInfo.processInfo.environment["CC_SUDO_SYNCKIT_FIXTURE"], !binary.isEmpty else {
            throw SynckitFixtureError.binaryMissing
        }
        var template = Array("/tmp/ccs-XXXXXX".utf8CString)
        guard let created = template.withUnsafeMutableBufferPointer({ mkdtemp($0.baseAddress) }) else {
            throw SynckitFixtureError.mkdtemp(errno)
        }
        home = URL(fileURLWithPath: String(cString: created), isDirectory: true)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = ["-home", home.path, "-reply", reply]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.standardError
        let input = Pipe()
        process.standardInput = input
        stdin = input
        lines = FixtureLines(output.fileHandleForReading)
        self.process = process
        try process.run()
        let ready = try await lines.next(timeout: .seconds(30))
        guard ready.hasPrefix("READY ") else {
            throw SynckitFixtureError.malformedLine(ready)
        }
        socketPath = String(ready.dropFirst("READY ".count))
    }

    func request() async throws -> Request {
        let line = try await lines.next(timeout: .seconds(5))
        let fields = line.split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[0] == "REQUEST", let payload = Data(base64Encoded: String(fields[2])) else {
            throw SynckitFixtureError.malformedLine(line)
        }
        return Request(operation: String(fields[1]), payload: payload)
    }

    func close() {
        try? stdin.fileHandleForWriting.close()
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: home)
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

private func withFixture<Result>(
    reply: String,
    body: (SynckitClient, SynckitFixture) async throws -> Result
) async throws -> Result {
    let fixture = try await SynckitFixture(reply: reply)
    defer { fixture.close() }
    let client = try SynckitClient(socketPath: SynckitClient.socketPath(home: fixture.home), deadline: 30)
    return try await withSynckitClient(client) { client in
        try await body(client, fixture)
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
    @Test(.enabled(if: ProcessInfo.processInfo.environment["CC_SUDO_SYNCKITD_HOME"] != nil))
    func publishedRuntimeAnswersStatus() async throws {
        let home = try #require(ProcessInfo.processInfo.environment["CC_SUDO_SYNCKITD_HOME"])
        #expect(SynckitClient.requiredRuntimeVersion == "0.40.0")
        let socketPath = try SynckitClient.socketPath(home: URL(fileURLWithPath: home, isDirectory: true))
        try await withSynckitClient(SynckitClient(socketPath: socketPath, deadline: 5)) { client in
            let status = try await client.status()
            #expect(status == SynckitStatus(meshSelf: "", hosts: []))
        }
    }

    @Test func socketPathMatchesTheProtocol2DaemonLayout() async throws {
        let fixture = try await SynckitFixture(reply: #"{"ok":true,"result":null}"#)
        defer { fixture.close() }
        #expect(try SynckitClient.socketPath(home: fixture.home) == fixture.socketPath)
        #expect(fixture.socketPath.hasSuffix("/.daemonkit/a/com.github.yasyf.synckit.serve/daemon.sock"))
    }

    @Test func statusDecodesTheMeshOverTheBusinessLane() async throws {
        try await withFixture(reply: """
        {"ok":true,"result":{"self":"me@studio","hosts":["me@laptop"],"manifests":2,"skipped":0}}
        """) { client, fixture in
            let status = try await client.status()
            #expect(status == SynckitStatus(meshSelf: "me@studio", hosts: ["me@laptop"]))

            let request = try await fixture.request()
            #expect(request.operation == SynckitClient.operation)
            let sent = try JSONSerialization.jsonObject(with: request.payload) as? [String: Any]
            #expect(sent?["method"] as? String == "status")
            #expect((sent?["params"] as? [String: Any])?.isEmpty == true)
        }
    }

    @Test func consentRequestRoundTripsOverTheProtocol2BusinessLane() async throws {
        try await withFixture(reply: """
        {"ok":true,"result":{"verdict":"approved","approved_by":"studio","routed":true,"cached":false,\
        "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"studio"}}}
        """) { client, fixture in
            let result = try await client.requestConsent(params)

            #expect(result.verdict == "approved")
            #expect(result.routed == true)
            let attestation = try #require(result.attestation)
            #expect(attestation.keyID == "kid")
            #expect(attestation.sig == "c2ln")
            #expect(attestation.signedBy == "studio")

            let request = try await fixture.request()
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
        _ = try await withFixture(reply: #"{"ok":false,"error":"prompt gate wedged"}"#) { client, _ in
            await #expect(throws: SynckitClient.ClientError.self) {
                _ = try await client.requestConsent(params)
            }
        }
    }

    @Test func concurrentRequestsCoalesceConnectionSetup() async throws {
        try await withFixture(reply: #"{"ok":true,"result":{"verdict":"approved"}}"#) { client, _ in
            async let first = client.requestConsent(params)
            async let second = client.requestConsent(params)
            let firstResult = try await first
            let secondResult = try await second
            #expect(firstResult.verdict == "approved")
            #expect(secondResult.verdict == "approved")
        }
    }

    @Test func missingSocketIsUnavailableUpstream() async throws {
        let client = SynckitClient(socketPath: "/nonexistent/daemon.sock", deadline: 1)
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
        try await withFixture(reply: reply) { client, _ in
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
            home: URL(fileURLWithPath: "/Users/alice", isDirectory: true),
            userID: 501,
            runner: runner
        )

        let result = try await bridge.requestConsent(params)

        #expect(result.verdict == "approved")
        let spawn = try #require(runner.spawns.first)
        #expect(spawn.executable == "/usr/bin/sudo")
        #expect(spawn.arguments == [
            "-u", "#501", "-H", RunClient.verifierPath,
            "synckit-bridge", "--socket", "/Users/alice/.daemonkit/a/com.github.yasyf.synckit.serve/daemon.sock",
        ])
        let bridged = try JSONDecoder().decode(SynckitConsentParams.self, from: #require(spawn.stdin))
        #expect(bridged.client == params.client)
        #expect(bridged.argv == params.argv)
        #expect(bridged.nonce == params.nonce)
    }

    @Test func bridgeTransportFailureIsUnavailable() async throws {
        let runner = FakeRunner { _, _ in .exit(2, stderr: "connect failed") }
        let bridge = SynckitBridgeClient(
            home: URL(fileURLWithPath: "/tmp/missing", isDirectory: true),
            userID: 501,
            runner: runner
        )

        await #expect(throws: SynckitClient.ClientError.self) {
            _ = try await bridge.requestConsent(params)
        }
    }
}
