import AuthKit
@testable import CCSudo
import CCSudoPhone
import Foundation
import Testing

private let phone = TailnetDevice(nodeID: "nPHONE", name: "yphone.tail1.ts.net.", os: "iOS")
private let macNonce = Data(repeating: 3, count: 24)

private struct Phone {
    let signing = TestSigner()
    let transport = TestSigner()
    let nonce = Data(repeating: 5, count: 24).base64EncodedString()

    var reveal: EnrollmentReveal {
        EnrollmentReveal(
            publicKey: signing.publicKeyBase64,
            transportKey: transport.publicKeyBase64,
            pushToken: "apns-token",
            nonce: nonce
        )
    }

    func commitment(code: String = "otc") -> EnrollmentCommitment {
        EnrollmentCommitment(code: code, commitment: reveal.commitment)
    }

    var confirmation: String {
        ConfirmationCode.of(code: "otc", mac: "yasyf-forge", reveal: reveal, macNonce: macNonce.base64EncodedString())
    }
}

private func enrollment() throws -> PhoneEnrollment {
    try PhoneEnrollment(name: "yphone", mac: "yasyf-forge", code: "otc", makeNonce: { macNonce })
}

private func temporaryStore() throws -> TrustStore {
    let directory = FileManager.default.temporaryDirectory
        .appending(component: "phone-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return TrustStore(directory: directory)
}

@Test func aWrongCodeIsRefusedAndCommitsNothing() throws {
    var session = try enrollment()
    #expect(try session.commit(Phone().commitment(code: "guess"), from: phone) == nil)
    #expect(session.committed == nil)
}

@Test func theTypedCodeMustMatchTheWholeExchange() throws {
    let device = Phone()
    var session = try enrollment()
    #expect(try session.commit(device.commitment(), from: phone) == macNonce.base64EncodedString())
    #expect(try session.reveal(device.reveal, from: phone) == phone)

    #expect(throws: PhoneEnrollment.EnrollmentError.confirmationMismatch) {
        _ = try session.confirm(typed: "000000")
    }
    let (record, key) = try session.confirm(typed: device.confirmation + "\n")
    #expect(key == device.signing.publicKeyX963)
    #expect(record == PhoneRecord(
        name: "yphone",
        nodeID: "nPHONE",
        device: "yphone.tail1.ts.net.",
        pushToken: "apns-token",
        transportKey: device.transport.publicKeyBase64,
        keyID: Attestation.keyID(publicKey: device.signing.publicKeyX963)
    ))
}

@Test func aRevealThatBreaksItsCommitmentEndsTheSession() throws {
    let device = Phone()
    var session = try enrollment()
    _ = try session.commit(device.commitment(), from: phone)
    let swapped = EnrollmentReveal(
        publicKey: TestSigner().publicKeyBase64,
        transportKey: device.transport.publicKeyBase64,
        pushToken: "apns-token",
        nonce: device.nonce
    )
    #expect(throws: PhoneEnrollment.EnrollmentError.commitmentMismatch) {
        _ = try session.reveal(swapped, from: phone)
    }
}

@Test func aRevealFromAnotherDeviceEndsTheSession() throws {
    let device = Phone()
    var session = try enrollment()
    _ = try session.commit(device.commitment(), from: phone)
    let other = TailnetDevice(nodeID: "nOTHER", name: "ipad.tail1.ts.net.", os: "iOS")
    #expect(throws: PhoneEnrollment.EnrollmentError.wrongDevice(device: "ipad.tail1.ts.net.")) {
        _ = try session.reveal(device.reveal, from: other)
    }
}

@Test func aMacEchoingTheCodeEndsTheSession() throws {
    var session = try enrollment()
    let mac = TailnetDevice(nodeID: "nMAC", name: "studio.tail1.ts.net.", os: "macOS")
    #expect(throws: PhoneEnrollment.EnrollmentError.notAPhone(device: "studio.tail1.ts.net.", os: "macOS")) {
        _ = try session.commit(Phone().commitment(), from: mac)
    }
}

@Test func aSecondCommitmentEndsTheSession() throws {
    var session = try enrollment()
    _ = try session.commit(Phone().commitment(), from: phone)
    let other = TailnetDevice(nodeID: "nOTHER", name: "ipad.tail1.ts.net.", os: "iOS")
    #expect(throws: PhoneEnrollment.EnrollmentError.secondDevice(device: "ipad.tail1.ts.net.")) {
        _ = try session.commit(Phone().commitment(), from: other)
    }
}

@Test func aMalformedKeyEndsTheSession() throws {
    var session = try enrollment()
    let bad = EnrollmentReveal(publicKey: "bm90IGEga2V5", transportKey: "bm90IGEga2V5", pushToken: "t", nonce: "n")
    _ = try session.commit(EnrollmentCommitment(code: "otc", commitment: bad.commitment), from: phone)
    #expect(throws: PhoneEnrollment.EnrollmentError.malformedKey("yphone.tail1.ts.net.")) {
        _ = try session.reveal(bad, from: phone)
    }
}

@Test func confirmingBeforeARevealThrows() throws {
    var session = try enrollment()
    _ = try session.commit(Phone().commitment(), from: phone)
    #expect(throws: PhoneEnrollment.EnrollmentError.noPhone) {
        _ = try session.confirm(typed: "123456")
    }
}

@Test func aTraversalNameIsRejectedBeforeListening() {
    #expect(throws: TrustStore.TrustError.self) {
        _ = try PhoneEnrollment(name: "../sudoers.d/evil", mac: "yasyf-forge", code: "otc")
    }
}

@Test func enrollingAPhoneWritesAPeerKeyAndARoutingRecordThatUntrustRemoves() throws {
    let store = try temporaryStore()
    let device = Phone()
    var session = try enrollment()
    _ = try session.commit(device.commitment(), from: phone)
    _ = try session.reveal(device.reveal, from: phone)
    let (record, key) = try session.confirm(typed: device.confirmation)

    try store.enroll(phone: record, publicKey: key)
    #expect(try store.peerKey(host: "yphone") == device.signing.publicKeyX963)
    #expect(try store.enrolledPhones() == [record])
    #expect(store.enrolledPeers() == ["yphone"])

    #expect(try store.remove(name: "yphone"))
    #expect(try store.enrolledPhones().isEmpty)
    #expect(store.enrolledPeers().isEmpty)
    #expect(try !store.remove(name: "yphone"))
}
