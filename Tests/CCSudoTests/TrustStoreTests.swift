@testable import CCSudo
import Foundation
import Testing

private func temporaryStore() throws -> TrustStore {
    let directory = FileManager.default.temporaryDirectory
        .appending(component: "trust-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return TrustStore(directory: directory)
}

@Test func selfKeyRoundTripsTheEnrolledBase64() throws {
    let store = try temporaryStore()
    let signer = TestSigner()
    try Data((signer.publicKeyBase64 + "\n").utf8).write(to: store.selfKeyURL)
    #expect(try store.selfKey() == signer.publicKeyX963)
}

@Test func missingSelfKeyThrowsTheTypedError() throws {
    let store = try temporaryStore()
    #expect(throws: TrustStore.TrustError.self) { try store.selfKey() }
}

@Test func malformedSelfKeyThrows() throws {
    let store = try temporaryStore()
    try Data("not base64!!!".utf8).write(to: store.selfKeyURL)
    #expect(throws: TrustStore.TrustError.self) { try store.selfKey() }
}

@Test func base64ThatIsNotAP256KeyThrows() throws {
    let store = try temporaryStore()
    try Data(Data("junk".utf8).base64EncodedString().utf8).write(to: store.selfKeyURL)
    #expect(throws: TrustStore.TrustError.self) { try store.selfKey() }
}

@Test func peerKeysResolveByHostName() throws {
    let store = try temporaryStore()
    let signer = TestSigner()
    try FileManager.default.createDirectory(at: store.peersDirectory, withIntermediateDirectories: true)
    try Data(signer.publicKeyBase64.utf8).write(to: store.peerKeyURL(host: "studio"))
    #expect(try store.peerKey(host: "studio") == signer.publicKeyX963)
    #expect(store.enrolledPeers() == ["studio"])
}

@Test func missingPeerKeyHardFails() throws {
    let store = try temporaryStore()
    #expect(throws: TrustStore.TrustError.self) { try store.peerKey(host: "studio") }
}

@Test(arguments: ["studio", "me@studio", "host-1.local", "a_b"])
func meshShapedPeerNamesAreAccepted(name: String) {
    #expect(throws: Never.self) { try TrustStore.validatePeerName(name) }
}

@Test(arguments: ["", "../etc", "a/b", ".hidden", "host name", "host\nname", "höst"])
func traversalShapedPeerNamesAreRejected(name: String) {
    #expect(throws: TrustStore.TrustError.self) { try TrustStore.validatePeerName(name) }
}
