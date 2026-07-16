import AuthKit
@testable import CCSudo
import Foundation
import Testing

@Test func deniedConsentClassifiesTo103() {
    #expect(ExitStatus(classifying: ConsentError.denied) == .denied)
    #expect(ExitStatus.denied.rawValue == 103)
}

@Test func unavailableTransportsClassifyTo104() {
    #expect(ExitStatus(classifying: ConsentError.unavailable("x")) == .unavailable)
    #expect(ExitStatus(classifying: ConsentError.screenLocked("x")) == .unavailable)
    #expect(ExitStatus.unavailable.rawValue == 104)
}

@Test func verificationFailuresClassifyTo105() {
    #expect(ExitStatus(classifying: VerifierError.signatureRejected(signedBy: "self")) == .verificationFailed)
    #expect(ExitStatus(classifying: TrustStore.TrustError.missingSelfKey(path: "p")) == .verificationFailed)
    #expect(ExitStatus(classifying: HelperTrust.HelperError.notInstalled(searched: [])) == .verificationFailed)
    #expect(ExitStatus(classifying: OriginIdentity.OriginError.unconfigured(path: "p")) == .verificationFailed)
    #expect(ExitStatus.verificationFailed.rawValue == 105)
}

@Test func versionSkewClassifiesTo106() {
    let skew = VersionSkewError(clientVersion: "0.1.0", verifierVersion: "0.2.0")
    #expect(ExitStatus(classifying: skew) == .versionSkew)
    #expect(ExitStatus.versionSkew.rawValue == 106)
    #expect(skew.message.contains("cc-sudo install"))
}

@Test func unrelatedErrorsAreNotClassified() {
    struct Other: Error {}
    #expect(ExitStatus(classifying: Other()) == nil)
}

@Test(arguments: [
    (Int32(0), "approved"),
    (Int32(7), "approved"),
    (Int32(103), "denied"),
    (Int32(104), "unavailable"),
    (Int32(105), "verification_failed"),
    (Int32(106), "version_skew"),
])
func verdictMapsTheDocumentedCodes(code: Int32, expected: String) {
    #expect(ExitStatus.verdict(forExitCode: code) == expected)
}
