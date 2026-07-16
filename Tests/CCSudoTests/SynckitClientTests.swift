@testable import CCSudo
import Foundation
import Testing

/// A one-shot ndjson server on a real unix socket: reads one line, answers the
/// scripted reply, and hands the captured request line back to the test — the
/// socket is a real boundary, not a mocked driver.
private final class OneShotServer: @unchecked Sendable {
    let path: String
    private let listener: Int32
    private var captured: Data = .init()
    private let done = DispatchSemaphore(value: 0)

    init(reply: String) throws {
        path = FileManager.default.temporaryDirectory
            .appending(component: "ck-\(UInt32.random(in: 0 ..< UInt32.max)).sock").path()
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        try #require(listener >= 0)

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        try #require(bytes.count < MemoryLayout.size(ofValue: address.sun_path))
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        try #require(bound == 0)
        try #require(listen(listener, 1) == 0)

        let acceptor = listener
        DispatchQueue.global().async { [weak self] in
            let connection = accept(acceptor, nil, nil)
            guard connection >= 0 else { return }
            defer { close(connection) }
            var buffer = [UInt8](repeating: 0, count: 65536)
            var line = Data()
            while !line.contains(0x0A) {
                let count = read(connection, &buffer, buffer.count)
                guard count > 0 else { break }
                line.append(contentsOf: buffer[0 ..< count])
            }
            self?.captured = line
            let out = Array((reply + "\n").utf8)
            _ = out.withUnsafeBytes { write(connection, $0.baseAddress, $0.count) }
            self?.done.signal()
        }
    }

    func requestLine() -> Data {
        done.wait()
        return captured
    }

    deinit {
        close(listener)
        try? FileManager.default.removeItem(atPath: path)
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

@Test func consentRequestRoundTripsTheFrozenWireShape() async throws {
    let server = try OneShotServer(reply: """
    {"ok":true,"result":{"verdict":"approved","approved_by":"studio","routed":true,"cached":false,\
    "attestation":{"key_id":"kid","sig":"c2ln","signed_by":"studio"}}}
    """)
    let client = SynckitClient(socketPath: server.path, deadline: 5)
    let result = try await client.requestConsent(params)

    #expect(result.verdict == "approved")
    #expect(result.routed == true)
    let attestation = try #require(result.attestation)
    #expect(attestation.keyID == "kid")
    #expect(attestation.sig == "c2ln")
    #expect(attestation.signedBy == "studio")

    let sent = try JSONSerialization.jsonObject(with: server.requestLine()) as? [String: Any]
    #expect(sent?["method"] as? String == "consent.request")
    let sentParams = try #require(sent?["params"] as? [String: Any])
    #expect(sentParams["client"] as? String == "cc-sudo")
    #expect(sentParams["argv"] as? [String] == ["dscacheutil", "-flushcache"])
    #expect(sentParams["ttl_ms"] as? Int == 0)
    #expect(sentParams["local_only"] as? Bool == false)
    #expect(sentParams["nonce"] as? String == params.nonce)
}

@Test func rpcErrorsThrow() async throws {
    let server = try OneShotServer(reply: #"{"ok":false,"error":"prompt gate wedged"}"#)
    let client = SynckitClient(socketPath: server.path, deadline: 5)
    await #expect(throws: SynckitClient.ClientError.self) {
        _ = try await client.requestConsent(params)
    }
}

@Test func missingSocketIsUnavailableUpstream() async throws {
    let source = SynckitConsentSource(
        client: SynckitClient(socketPath: "/nonexistent/rpc.sock", deadline: 1),
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
    let server = try OneShotServer(reply: reply)
    let source = SynckitConsentSource(
        client: SynckitClient(socketPath: server.path, deadline: 5),
        selfIdentity: selfIdentity
    )
    return try await source.obtainSignature(
        ConsentRequest(argv: ["dscacheutil", "-flushcache"], nonce: Data(repeating: 2, count: 24))
    )
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
