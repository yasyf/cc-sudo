@testable import CCSudo
import Foundation
import Testing

private func temporaryStore() throws -> TrustStore {
    let directory = FileManager.default.temporaryDirectory
        .appending(component: "peer-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return TrustStore(directory: directory)
}

@Test func trustFetchesOverSSHAndEnrollsThePeerKey() async throws {
    let store = try temporaryStore()
    let signer = TestSigner()
    let runner = FakeRunner { _, _ in .exit(0, stdout: signer.publicKeyBase64 + "\n") }
    let trust = PeerTrust(runner: runner, store: store, euid: { 0 })

    let keyID = try await trust.trust(peer: "studio")
    #expect(keyID.count == 64)
    #expect(try store.peerKey(host: "studio") == signer.publicKeyX963)

    let spawn = try #require(runner.spawns.first)
    #expect(spawn.executable == "/usr/bin/ssh")
    #expect(spawn.arguments == ["-o", "BatchMode=yes", "--", "studio", "cat", "/etc/cc-sudo/trusted/self.pub"])
}

@Test func trustRequiresRoot() async throws {
    let trust = try PeerTrust(runner: FakeRunner { _, _ in .exit(0) }, store: temporaryStore(), euid: { 501 })
    await #expect(throws: PeerTrust.PeerTrustError.self) {
        _ = try await trust.trust(peer: "studio")
    }
}

@Test func trustRejectsAGarbageKeyWithoutWriting() async throws {
    let store = try temporaryStore()
    let runner = FakeRunner { _, _ in .exit(0, stdout: "definitely not a key") }
    let trust = PeerTrust(runner: runner, store: store, euid: { 0 })
    await #expect(throws: TrustStore.TrustError.self) {
        _ = try await trust.trust(peer: "studio")
    }
    #expect(store.enrolledPeers().isEmpty)
}

@Test func trustRejectsTraversalPeerNamesBeforeAnySSH() async throws {
    let runner = FakeRunner { _, _ in .exit(0) }
    let trust = try PeerTrust(runner: runner, store: temporaryStore(), euid: { 0 })
    await #expect(throws: TrustStore.TrustError.self) {
        _ = try await trust.trust(peer: "../../etc/sudoers.d/evil")
    }
    #expect(runner.spawns.isEmpty)
}

@Test func failedFetchPropagates() async throws {
    let runner = FakeRunner { _, _ in .exit(255, stderr: "connection refused") }
    let trust = try PeerTrust(runner: runner, store: temporaryStore(), euid: { 0 })
    await #expect(throws: PeerTrust.PeerTrustError.self) {
        _ = try await trust.trust(peer: "studio")
    }
}

@Test(arguments: ["-F", "-oProxyCommand=x", "-Fcat", "--"])
func trustRejectsDashLedPeerNamesBeforeAnySSH(name: String) async throws {
    let runner = FakeRunner { _, _ in .exit(0) }
    let trust = try PeerTrust(runner: runner, store: temporaryStore(), euid: { 0 })
    await #expect(throws: TrustStore.TrustError.self) {
        _ = try await trust.trust(peer: name)
    }
    #expect(runner.spawns.isEmpty)
}
