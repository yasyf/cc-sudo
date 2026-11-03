import AuthKit
@testable import CCSudo
import CCSudoPhone
import Foundation
import Testing

private let phone = TailnetDevice(nodeID: "nPHONE", name: "yphone.tail1.ts.net.", os: "iOS")

private func submission(_ signer: TestSigner, code: String = "otc") -> EnrollmentSubmission {
    EnrollmentSubmission(code: code, publicKey: signer.publicKeyBase64, pushToken: "apns-token")
}

private func temporaryStore() throws -> TrustStore {
    let directory = FileManager.default.temporaryDirectory
        .appending(component: "phone-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return TrustStore(directory: directory)
}

@Test func aWrongCodeIsRefusedAndHoldsNothing() throws {
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    #expect(try !enrollment.receive(submission(TestSigner(), code: "guess"), from: phone))
    #expect(enrollment.held == nil)
}

@Test func theTypedCodeMustMatchTheHeldKey() throws {
    let signer = TestSigner()
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    #expect(try enrollment.receive(submission(signer), from: phone))

    #expect(throws: PhoneEnrollment.EnrollmentError.confirmationMismatch) {
        _ = try enrollment.confirm(typed: "000000")
    }
    let (record, key) = try enrollment.confirm(typed: ConfirmationCode.of(publicKey: signer.publicKeyX963) + "\n")
    #expect(key == signer.publicKeyX963)
    #expect(record == PhoneRecord(
        name: "yphone",
        nodeID: "nPHONE",
        device: "yphone.tail1.ts.net.",
        pushToken: "apns-token",
        keyID: Attestation.keyID(publicKey: signer.publicKeyX963)
    ))
}

@Test func aMacEchoingTheCodeEndsTheSession() throws {
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    let mac = TailnetDevice(nodeID: "nMAC", name: "studio.tail1.ts.net.", os: "macOS")
    #expect(throws: PhoneEnrollment.EnrollmentError.notAPhone(device: "studio.tail1.ts.net.", os: "macOS")) {
        _ = try enrollment.receive(submission(TestSigner()), from: mac)
    }
}

@Test func aSecondDeviceEchoingTheCodeEndsTheSession() throws {
    let signer = TestSigner()
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    #expect(try enrollment.receive(submission(signer), from: phone))
    #expect(try enrollment.receive(submission(signer), from: phone))

    let other = TailnetDevice(nodeID: "nOTHER", name: "ipad.tail1.ts.net.", os: "iOS")
    #expect(throws: PhoneEnrollment.EnrollmentError.secondDevice(device: "ipad.tail1.ts.net.")) {
        _ = try enrollment.receive(submission(TestSigner()), from: other)
    }
    #expect(throws: PhoneEnrollment.EnrollmentError.secondDevice(device: "yphone.tail1.ts.net.")) {
        _ = try enrollment.receive(submission(TestSigner()), from: phone)
    }
}

@Test func aMalformedKeyEndsTheSession() throws {
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    let bad = EnrollmentSubmission(code: "otc", publicKey: "bm90IGEga2V5", pushToken: "t")
    #expect(throws: PhoneEnrollment.EnrollmentError.malformedKey("yphone.tail1.ts.net.")) {
        _ = try enrollment.receive(bad, from: phone)
    }
}

@Test func confirmingWithNoPhoneThrows() throws {
    let enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    #expect(throws: PhoneEnrollment.EnrollmentError.noPhone) {
        _ = try enrollment.confirm(typed: "123456")
    }
}

@Test func aTraversalNameIsRejectedBeforeListening() {
    #expect(throws: TrustStore.TrustError.self) {
        _ = try PhoneEnrollment(name: "../sudoers.d/evil", code: "otc")
    }
}

@Test func enrollingAPhoneWritesAPeerKeyAndARoutingRecordThatUntrustRemoves() throws {
    let store = try temporaryStore()
    let signer = TestSigner()
    var enrollment = try PhoneEnrollment(name: "yphone", code: "otc")
    _ = try enrollment.receive(submission(signer), from: phone)
    let (record, key) = try enrollment.confirm(typed: ConfirmationCode.of(publicKey: signer.publicKeyX963))

    try store.enroll(phone: record, publicKey: key)
    #expect(try store.peerKey(host: "yphone") == signer.publicKeyX963)
    #expect(try store.enrolledPhones() == [record])
    #expect(store.enrolledPeers() == ["yphone"])

    #expect(try store.remove(name: "yphone"))
    #expect(try store.enrolledPhones().isEmpty)
    #expect(store.enrolledPeers().isEmpty)
    #expect(try !store.remove(name: "yphone"))
}
