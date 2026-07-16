@testable import CCSudo
import Foundation
import Testing

@Test func noncesAre24FreshBytes() throws {
    let first = try Nonce.generate()
    let second = try Nonce.generate()
    #expect(first.count == 24)
    #expect(second.count == 24)
    #expect(first != second)
}

@Test func promptStrategyRequiresTheInvokerToOwnTheConsole() {
    let console = ConsoleUser(name: "yasyf", uid: 501)
    #expect(PromptStrategy.select(console: console, invokerUID: 501) == .localThenSynckit(console: console))
    #expect(PromptStrategy.select(console: console, invokerUID: 502) == .synckitOnly)
    #expect(PromptStrategy.select(console: nil, invokerUID: 501) == .synckitOnly)
    #expect(PromptStrategy.select(console: console, invokerUID: nil) == .synckitOnly)
}

@Test func sudoInvokerUIDParsesTheSudoEnvironment() {
    #expect(PromptStrategy.sudoInvokerUID(environment: ["SUDO_UID": "501"]) == 501)
    #expect(PromptStrategy.sudoInvokerUID(environment: [:]) == nil)
    #expect(PromptStrategy.sudoInvokerUID(environment: ["SUDO_UID": "junk"]) == nil)
}

/// Doctor's non-mutating dry run must never crash, whatever this machine has
/// installed; individual checks report their own pass/fail.
@Test func doctorDryRunProducesEveryCheck() async {
    let results = await Doctor(runner: FakeRunner { _, _ in .exit(0) }).checks()
    #expect(results.map(\.name) == [
        "verifier", "sudoers", "authkit pin", "synckitd",
        "self key", "peer keys", "origin identity", "prompt path",
    ])
}
