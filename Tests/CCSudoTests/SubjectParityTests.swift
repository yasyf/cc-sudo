import AuthKit
import CCSudo
import Foundation
import Testing

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

/// The frozen cross-repo subject contract, proved against authkit's
/// known-answer vectors: canonical(argv) = 8-byte big-endian UTF-8 byte count
/// per argument then the bytes; subject = sha256(canonical ‖ 0x00 ‖ origin).
/// cc-sudo consumes AuthKit.Subject rather than re-deriving, so this parity
/// test pins the dependency's behavior from the verifier's side.
@Test(arguments: [
    (["dscacheutil", "-flushcache"], "", "533e36c30a841b85ce9a562596dcabde8c251fa62ce9fb87454f008bb3c597b5"),
    (["ab", "c"], "", "7add9366540656f31f5ad408663bf167291ae93f69494c9f9cb178fcc58cd250"),
    (["a", "bc"], "", "c30e79fdcb1292bf0cddaf7cf6d0303b5e96222ba1d33f6f169e82977a3e6fad"),
    ([""], "", "3e7077fd2f66d689e0cee6a7cf5b37bf2dca7c979af356d0a31cbc5c85605c7d"),
    (["reboot"], "studio", "5634163ce24b126a802815c2035fdb14f0a1720f754c05bb0292240d496d0a13"),
    (["reboot"], "", "4e84672feb5de3b1cb55bbf1d0f6ae934502524a99a0b2c49cd039ae0379a729"),
])
func subjectDigestMatchesTheFrozenKnownAnswers(argv: [String], originHost: String, expected: String) {
    #expect(hex(Subject.digest(argv: argv, originHost: originHost)) == expected)
}

@Test func verifyAgreesWithTheHelperSideDigest() throws {
    let signer = TestSigner()
    let nonce = Data(repeating: 9, count: 24)
    let argv = ["reboot"]
    let signature = try signer.sign(nonce: nonce, argv: argv, originHost: "studio")
    #expect(try Attestation.verify(
        signature: signature,
        nonce: nonce,
        argv: argv,
        originHost: "studio",
        publicKeyX963: signer.publicKeyX963
    ))
    #expect(try !Attestation.verify(
        signature: signature,
        nonce: nonce,
        argv: argv,
        originHost: "laptop",
        publicKeyX963: signer.publicKeyX963
    ))
}
