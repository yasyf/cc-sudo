import AuthKit
import Foundation
import os

public enum VerifierError: Error, Sendable {
    case emptyArgv
    case signatureRejected(signedBy: String)
}

/// The root-side flow — the crux of cc-sudo. In order, with no TOCTOU gap:
///
///   1. Generate a fresh 24-byte nonce (replay is dead).
///   2. Reverse-pin authkit: locate the bundle at its known path and validate
///      it against the pinned designated requirement BEFORE trusting any
///      signature (the unspoofable anchor — root spawns that exact path).
///   3. Obtain the signature through a ConsentSource strategy: the local
///      `launchctl asuser` helper spawn, falling back to the synckitd socket.
///   4. Recompute subject_bytes = sha256(canonical(argv) ‖ 0x00 ‖
///      utf8(origin_host)) with the origin_host THIS verifier trusts: "" for a
///      local signature, this host's own recorded identity for a peer's.
///   5. Verify the ECDSA signature over nonce ‖ subject_bytes against the
///      enrolled public key for whoever signed. Missing key = hard fail.
///   6. On success only, exec the EXACT argv that was hashed (TOCTOU is dead:
///      approved digest == executed argv).
public struct Verifier: Sendable {
    /// The boundaries the flow touches; tests fake every one so no sudo,
    /// launchctl, helper, or exec runs in CI.
    public struct Dependencies: Sendable {
        public var generateNonce: @Sendable () throws -> Data
        public var pinHelper: @Sendable () throws -> URL
        public var consentSource: @Sendable (_ pinnedHelper: URL) -> any ConsentSource
        public var selfKey: @Sendable () throws -> Data
        public var peerKey: @Sendable (_ host: String) throws -> Data
        public var originIdentity: @Sendable () throws -> String
        public var execute: @Sendable (_ argv: [String]) throws -> Never

        public init(
            generateNonce: @escaping @Sendable () throws -> Data,
            pinHelper: @escaping @Sendable () throws -> URL,
            consentSource: @escaping @Sendable (_ pinnedHelper: URL) -> any ConsentSource,
            selfKey: @escaping @Sendable () throws -> Data,
            peerKey: @escaping @Sendable (_ host: String) throws -> Data,
            originIdentity: @escaping @Sendable () throws -> String,
            execute: @escaping @Sendable (_ argv: [String]) throws -> Never
        ) {
            self.generateNonce = generateNonce
            self.pinHelper = pinHelper
            self.consentSource = consentSource
            self.selfKey = selfKey
            self.peerKey = peerKey
            self.originIdentity = originIdentity
            self.execute = execute
        }
    }

    let dependencies: Dependencies

    public init(dependencies: Dependencies) {
        self.dependencies = dependencies
    }

    /// Runs the whole flow and never returns: on approval the process becomes
    /// the target command; every other outcome throws.
    public func authorizeAndRun(argv: [String]) async throws -> Never {
        guard !argv.isEmpty else { throw VerifierError.emptyArgv }

        let nonce = try dependencies.generateNonce()
        let pinnedHelper = try dependencies.pinHelper()
        let source = dependencies.consentSource(pinnedHelper)
        let consent = try await source.obtainSignature(ConsentRequest(argv: argv, nonce: nonce))

        let publicKey: Data
        let originHost: String
        let signedBy: String
        switch consent.origin {
        case .local:
            publicKey = try dependencies.selfKey()
            originHost = ""
            signedBy = "self"
        case let .peer(host):
            publicKey = try dependencies.peerKey(host)
            originHost = try dependencies.originIdentity()
            signedBy = host
        }

        let valid = try Attestation.verify(
            signature: consent.signature,
            nonce: nonce,
            argv: argv,
            originHost: originHost,
            publicKeyX963: publicKey
        )
        guard valid else {
            Logger.verifier.error("signature rejected (signed_by \(signedBy, privacy: .public))")
            throw VerifierError.signatureRejected(signedBy: signedBy)
        }

        Logger.verifier.info(
            "approved: \(Subject.argvDigestHex(argv: argv), privacy: .public) signed_by \(signedBy, privacy: .public)"
        )
        try dependencies.execute(argv)
    }
}
