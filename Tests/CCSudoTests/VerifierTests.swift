import AuthKit
@testable import CCSudo
import Foundation
import Testing

// argv[0] is ABSOLUTE: the unprivileged run side resolves it before signing,
// and the root verifier refuses a non-absolute argv[0] fail-closed.
private let argv = ["/usr/sbin/dscacheutil", "-flushcache"]
private let nonceA = Data((0 ..< 24).map { UInt8($0) })
private let nonceB = Data((100 ..< 124).map { UInt8($0) })

@Test func approvedLocalSignatureExecsTheExactArgv() async throws {
    let signer = TestSigner()
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: request.argv, originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    let executed = await #expect(throws: Executed.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
    #expect(executed?.argv == argv)
}

@Test func tamperedArgvIsRejectedAndNothingRuns() async throws {
    let signer = TestSigner()
    // The helper signed a benign command; the verifier is asked to run rm.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: ["/bin/ls"], originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: ["/bin/rm", "-rf", "/"])
    }
}

@Test func wrongOriginHostIsRejected() async throws {
    let signer = TestSigner()
    // Signed as if requested from "studio", but presented as a LOCAL approval
    // (origin_host "") — the amended origin binding must reject it.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: request.argv, originHost: "studio"),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func routedSignatureVerifiesAgainstThePeerKeyAndOwnIdentity() async throws {
    let peerSigner = TestSigner()
    // The peer "studio" signs with requested_from = OUR identity ("laptop").
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: peerSigner.sign(nonce: request.nonce, argv: request.argv, originHost: "laptop"),
            origin: .peer(host: "studio")
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA],
        source: source,
        selfKey: nil,
        peerKeys: ["studio": peerSigner.publicKeyX963],
        originIdentity: "laptop"
    ))
    let executed = await #expect(throws: Executed.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
    #expect(executed?.argv == argv)
}

@Test func routedSignatureOverASpoofedProvenanceLabelIsRejected() async throws {
    let peerSigner = TestSigner()
    // The peer signed a subject claiming the request came from "evil-host";
    // the verifier recomputes with the identity IT actually holds ("laptop").
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: peerSigner.sign(nonce: request.nonce, argv: request.argv, originHost: "evil-host"),
            origin: .peer(host: "studio")
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA],
        source: source,
        selfKey: nil,
        peerKeys: ["studio": peerSigner.publicKeyX963],
        originIdentity: "laptop"
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func replayedNonceIsRejected() async throws {
    let signer = TestSigner()
    let staleSignature = try signer.sign(nonce: nonceA, argv: argv, originHost: "")
    // The attacker replays a previously captured signature; the verifier
    // generated a FRESH nonce for this run.
    let source = ScriptedConsentSource { _ in
        SignedConsent(keyID: "k", signature: staleSignature, origin: .local)
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceB], source: source, selfKey: signer.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func wrongEnrolledKeyIsRejected() async throws {
    let signer = TestSigner()
    let otherKey = TestSigner()
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: request.argv, originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: otherKey.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func missingEnrolledKeyHardFails() async throws {
    let signer = TestSigner()
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: request.argv, originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: nil
    ))
    await #expect(throws: TrustStore.TrustError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func missingPeerKeyHardFailsARoutedApproval() async throws {
    let peerSigner = TestSigner()
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: peerSigner.sign(nonce: request.nonce, argv: request.argv, originHost: "laptop"),
            origin: .peer(host: "studio")
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: nil, peerKeys: [:]
    ))
    await #expect(throws: TrustStore.TrustError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func deniedConsentPropagatesWithoutExec() async throws {
    let source = ScriptedConsentSource { _ in throw ConsentError.denied }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: TestSigner().publicKeyX963
    ))
    await #expect(throws: ConsentError.denied) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

@Test func emptyArgvIsRefused() async throws {
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA],
        source: ScriptedConsentSource { _ in throw ConsentError.denied },
        selfKey: nil
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: [])
    }
}

// MARK: - M2: a non-absolute argv[0] reaching the verifier is refused

@Test func aRelativeExecutableReachingTheVerifierIsRejected() async throws {
    let signer = TestSigner()
    // A validly-signed but non-absolute argv[0] must be rejected fail-closed,
    // before any signature work — root never runs a PATH search.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: ["dscacheutil", "-flushcache"], originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    let error = await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: ["dscacheutil", "-flushcache"])
    }
    guard case .nonAbsoluteExecutable = error else {
        Issue.record("want nonAbsoluteExecutable, got \(String(describing: error))")
        return
    }
}

// MARK: - m2 regression blind spots

/// (1) A verifier that signs/verifies only [argv[0]] but executes the FULL argv
/// must fail — argv truncation before signing is a divergence.
@Test func argvTruncatedBeforeSigningFailsVerification() async throws {
    let signer = TestSigner()
    // The signature covers only argv[0]; the verifier runs the full argv.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: [request.argv[0]], originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

/// (3) A routed approval is verified against the signed_by-selected key only. A
/// signature from peer A presented as signed_by peer B selects B's key and is
/// rejected — the verifier never tries every enrolled key.
@Test func routedApprovalVerifiesOnlyTheSignedBySelectedKey() async throws {
    let peerA = TestSigner()
    let peerB = TestSigner()
    // Peer A actually produced the signature, but signed_by claims peer B.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: peerA.sign(nonce: request.nonce, argv: request.argv, originHost: "laptop"),
            origin: .peer(host: "beta")
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA],
        source: source,
        selfKey: nil,
        peerKeys: ["alpha": peerA.publicKeyX963, "beta": peerB.publicKeyX963],
        originIdentity: "laptop"
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

/// (4) Calling the SAME verifier twice proves per-call nonce freshness: the
/// source signs a FIXED nonce, so the second call (a fresh nonce) rejects.
@Test func perCallNonceFreshnessAcrossTwoCalls() async throws {
    let signer = TestSigner()
    // Always sign over nonceA regardless of the request's actual nonce.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: nonceA, argv: request.argv, originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA, nonceB], source: source, selfKey: signer.publicKeyX963
    ))
    // Call 1 uses nonceA → the fixed-nonce signature verifies → exec.
    let executed = await #expect(throws: Executed.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
    #expect(executed?.argv == argv)
    // Call 2 uses a FRESH nonceB → the same fixed-nonce signature is stale.
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

/// (5) A verification that THROWS (malformed key material) is treated as a
/// rejection — never as an approval, never an exec.
@Test func throwingVerificationIsTreatedAsRejection() async throws {
    let signer = TestSigner()
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: signer.sign(nonce: request.nonce, argv: request.argv, originHost: ""),
            origin: .local
        )
    }
    // The enrolled key bytes are garbage: Attestation.verify throws rather than
    // returning false. The verifier must propagate that as a hard failure.
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: Data("not a key".utf8)
    ))
    await #expect(throws: (any Error).self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}

/// (6) One combined adversarial routed E2E: a forged signed_by peer, a real SE
/// signature over a SPOOFED origin_host, verified against the real enrolled peer
/// key. The origin verifier recomputes with ITS own identity and rejects.
@Test func combinedAdversarialRoutedApprovalIsRejected() async throws {
    let peer = TestSigner()
    let decoy = TestSigner()
    // The peer signs a subject claiming the request came from "evil-origin"
    // (forged provenance), routed onto the peer path with a genuine key.
    let source = ScriptedConsentSource { request in
        try SignedConsent(
            keyID: "k",
            signature: peer.sign(nonce: request.nonce, argv: request.argv, originHost: "evil-origin"),
            origin: .peer(host: "studio")
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA],
        source: source,
        selfKey: nil,
        peerKeys: ["studio": peer.publicKeyX963, "other": decoy.publicKeyX963],
        originIdentity: "laptop"
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: argv)
    }
}
