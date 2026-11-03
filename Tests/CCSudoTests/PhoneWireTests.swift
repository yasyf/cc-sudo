import AuthKit
import CCSudoPhone
import CryptoKit
import Foundation
import Testing

@Test func confirmationCodeAndCommitmentMatchTheirKnownAnswers() {
    let reveal = EnrollmentReveal(publicKey: "PK", transportKey: "TK", pushToken: "apns", nonce: "Np")
    #expect(reveal.commitment == "nHiC1clyH0xO92KgGQ6rL1qfV8apDRv2+9Fs2fRLses=")
    #expect(ConfirmationCode.of(code: "otc", mac: "yasyf-forge", reveal: reveal, macNonce: "Nm") == "951824")
}

@Test func confirmationCodeCoversThePushTokenAndTheMacNonce() {
    let reveal = EnrollmentReveal(publicKey: "PK", transportKey: "TK", pushToken: "apns", nonce: "Np")
    let swapped = EnrollmentReveal(publicKey: "PK", transportKey: "TK", pushToken: "attacker", nonce: "Np")
    let code = ConfirmationCode.of(code: "otc", mac: "yasyf-forge", reveal: reveal, macNonce: "Nm")
    #expect(ConfirmationCode.of(code: "otc", mac: "yasyf-forge", reveal: swapped, macNonce: "Nm") != code)
    #expect(ConfirmationCode.of(code: "otc", mac: "yasyf-forge", reveal: reveal, macNonce: "Nm2") != code)
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
    let reveal = try JSONDecoder().decode(
        EnrollmentReveal.self,
        from: Data(#"{"public_key":"k","transport_key":"t","push_token":"p","nonce":"n"}"#.utf8)
    )
    #expect(reveal == EnrollmentReveal(publicKey: "k", transportKey: "t", pushToken: "p", nonce: "n"))

    let answer = ApprovalAnswer(id: "r1", nonce: "n", verdict: .approved, keyID: "kid", sig: "s")
    let object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(answer)) as? [String: String])
    #expect(object == ["id": "r1", "nonce": "n", "verdict": "approved", "key_id": "kid", "sig": "s"])
}

@Test func transportAuthBindsMethodIDAndBody() {
    let get = TransportAuth.message(method: "GET", id: "r1", body: Data())
    #expect(get != TransportAuth.message(method: "POST", id: "r1", body: Data()))
    #expect(get != TransportAuth.message(method: "GET", id: "r2", body: Data()))
    #expect(
        TransportAuth.message(method: "POST", id: "r1", body: Data("a".utf8))
            != TransportAuth.message(method: "POST", id: "r1", body: Data("b".utf8))
    )
}
