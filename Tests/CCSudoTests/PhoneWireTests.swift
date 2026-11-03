import AuthKit
import CCSudoPhone
import CryptoKit
import Foundation
import Testing

@Test(arguments: [
    (Data(repeating: 1, count: 65), "415220"),
    (Data([4] + Array(0 ..< 64)), "640413"),
])
func confirmationCodeIsSixDigitsOfTheKeyDigest(key: Data, expected: String) {
    #expect(ConfirmationCode.of(publicKey: key) == expected)
}

@Test func phoneSignatureVerifiesAsAPeerSignatureForTheEnrolledMac() throws {
    let signer = TestSigner()
    let nonce = Data(repeating: 7, count: 24)
    let argv = ["/usr/bin/dscacheutil", "-flushcache"]
    let signature = try signer.privateKey
        .signature(for: PhoneSignature.message(nonce: nonce, argv: argv, mac: "yasyf-forge"))
        .derRepresentation

    #expect(try Attestation.verify(
        signature: signature, nonce: nonce, argv: argv, originHost: "yasyf-forge", publicKeyX963: signer.publicKeyX963
    ))
    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, argv: argv, originHost: "studio", publicKeyX963: signer.publicKeyX963
    ))
    #expect(try !Attestation.verify(
        signature: signature, nonce: nonce, argv: argv + ["-x"], originHost: "yasyf-forge", publicKeyX963: signer.publicKeyX963
    ))
}

@Test(arguments: [
    (["/bin/sh", "-c", "echo hi"], true),
    (["/usr/bin/python3", "-"], true),
    (["/opt/homebrew/bin/python3.13", "x.py"], true),
    (["/usr/bin/osascript", "-e", "beep"], true),
    (["/usr/bin/tee", "/etc/hosts"], true),
    (["/usr/bin/dscacheutil", "-flushcache"], false),
    (["/usr/sbin/shutdown", "-r", "now"], false),
])
func scriptRunnersGetTheWarningBand(argv: [String], warns: Bool) {
    #expect(ScriptRunner.runsScript(argv) == warns)
}

@Test func wireKeysMatchTheSynckitContract() throws {
    let submission = try JSONDecoder().decode(
        EnrollmentSubmission.self,
        from: Data(#"{"code":"c","public_key":"k","push_token":"t"}"#.utf8)
    )
    #expect(submission == EnrollmentSubmission(code: "c", publicKey: "k", pushToken: "t"))

    let answer = ApprovalAnswer(id: "r1", nonce: "n", verdict: .approved, keyID: "kid", sig: "s")
    let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(answer)) as? [String: String])
    #expect(object == ["id": "r1", "nonce": "n", "verdict": "approved", "key_id": "kid", "sig": "s"])
}
