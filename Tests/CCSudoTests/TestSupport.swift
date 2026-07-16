import AuthKit
@testable import CCSudo
import CryptoKit
import Foundation

/// An ephemeral P-256 signer standing in for the Secure-Enclave key: same
/// curve, same ecdsaSignatureMessageX962SHA256 format, no hardware or
/// entitlements — the spike proved the crypto is identical, so the verifier's
/// checks are provable headless.
struct TestSigner {
    let privateKey = P256.Signing.PrivateKey()

    var publicKeyX963: Data {
        privateKey.publicKey.x963Representation
    }

    var publicKeyBase64: String {
        publicKeyX963.base64EncodedString()
    }

    func sign(nonce: Data, argv: [String], originHost: String) throws -> Data {
        let subject = Subject.digest(argv: argv, originHost: originHost)
        return try privateKey.signature(for: Attestation.message(nonce: nonce, subject: subject))
            .derRepresentation
    }
}

/// A ConsentSource whose behavior the test scripts.
struct ScriptedConsentSource: ConsentSource {
    let respond: @Sendable (ConsentRequest) throws -> SignedConsent

    func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent {
        try respond(request)
    }
}

/// The sentinel a fake executor throws instead of exec'ing, carrying the argv
/// the verifier approved.
struct Executed: Error {
    let argv: [String]
}

/// A ProcessRunner that returns canned results and records every spawn.
final class FakeRunner: ProcessRunner, @unchecked Sendable {
    struct Spawn {
        let executable: String
        let arguments: [String]
        let stdin: Data?
    }

    private let lock = NSLock()
    private var recorded: [Spawn] = []
    let respond: @Sendable (String, [String]) -> SubprocessResult

    init(respond: @escaping @Sendable (String, [String]) -> SubprocessResult) {
        self.respond = respond
    }

    var spawns: [Spawn] {
        lock.withLock { recorded }
    }

    func run(
        executable: String,
        arguments: [String],
        stdin: Data?,
        environment _: [String: String]?
    ) async throws -> SubprocessResult {
        lock.withLock {
            recorded.append(Spawn(executable: executable, arguments: arguments, stdin: stdin))
        }
        return respond(executable, arguments)
    }
}

extension SubprocessResult {
    static func exit(_ code: Int32, stdout: String = "", stderr: String = "") -> SubprocessResult {
        SubprocessResult(exitCode: code, stdout: Data(stdout.utf8), stderr: Data(stderr.utf8))
    }
}

func makeVerifierDependencies(
    nonces: [Data],
    source: any ConsentSource,
    selfKey: Data?,
    peerKeys: [String: Data] = [:],
    originIdentity: String = "laptop"
) -> Verifier.Dependencies {
    let queue = NonceQueue(nonces: nonces)
    return Verifier.Dependencies(
        generateNonce: { queue.next() },
        pinHelper: { URL(filePath: "/pinned/authkit.app/Contents/MacOS/authkit") },
        consentSource: { _ in source },
        selfKey: {
            guard let selfKey else { throw TrustStore.TrustError.missingSelfKey(path: "/etc/cc-sudo/trusted/self.pub") }
            return selfKey
        },
        peerKey: { host in
            guard let key = peerKeys[host] else {
                throw TrustStore.TrustError.missingPeerKey(host: host, path: "/etc/cc-sudo/trusted/peers/\(host).pub")
            }
            return key
        },
        originIdentity: { originIdentity },
        execute: { argv in throw Executed(argv: argv) }
    )
}

final class NonceQueue: @unchecked Sendable {
    private let lock = NSLock()
    private var nonces: [Data]

    init(nonces: [Data]) {
        self.nonces = nonces
    }

    func next() -> Data {
        lock.withLock { nonces.removeFirst() }
    }
}
