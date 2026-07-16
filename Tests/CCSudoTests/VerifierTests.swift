import AuthKit
@testable import CCSudo
import Foundation
import Testing

private let argv = ["dscacheutil", "-flushcache"]
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
            signature: signer.sign(nonce: request.nonce, argv: ["ls"], originHost: ""),
            origin: .local
        )
    }
    let verifier = Verifier(dependencies: makeVerifierDependencies(
        nonces: [nonceA], source: source, selfKey: signer.publicKeyX963
    ))
    await #expect(throws: VerifierError.self) {
        try await verifier.authorizeAndRun(argv: ["rm", "-rf", "/"])
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
