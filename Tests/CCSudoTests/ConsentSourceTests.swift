import AuthKit
@testable import CCSudo
import Foundation
import Testing

private let request = ConsentRequest(
    argv: ["dscacheutil", "-flushcache"],
    nonce: Data((0 ..< 24).map { UInt8($0) })
)

// MARK: - FallbackConsentSource routing invariants

@Test func fallbackIsConsultedWhenPrimaryIsUnavailable() async throws {
    let expected = SignedConsent(keyID: "fallback", signature: Data([1]), origin: .peer(host: "studio"))
    let source = FallbackConsentSource(
        primary: ScriptedConsentSource { _ in throw ConsentError.unavailable("no sheet") },
        fallback: ScriptedConsentSource { _ in expected }
    )
    let consent = try await source.obtainSignature(request)
    #expect(consent.keyID == "fallback")
}

@Test func fallbackIsConsultedWhenTheScreenIsLocked() async throws {
    let source = FallbackConsentSource(
        primary: ScriptedConsentSource { _ in throw ConsentError.screenLocked("locked") },
        fallback: ScriptedConsentSource { _ in SignedConsent(keyID: "peer", signature: Data(), origin: .local) }
    )
    let consent = try await source.obtainSignature(request)
    #expect(consent.keyID == "peer")
}

@Test func denialIsTerminalAndNeverRoutesToTheFallback() async throws {
    let source = FallbackConsentSource(
        primary: ScriptedConsentSource { _ in throw ConsentError.denied },
        fallback: ScriptedConsentSource { _ in
            Issue.record("fallback must not be consulted after a denial")
            return SignedConsent(keyID: "never", signature: Data(), origin: .local)
        }
    )
    await #expect(throws: ConsentError.denied) {
        _ = try await source.obtainSignature(request)
    }
}

@Test func malformedResponsesAreFatalNotRoutable() async throws {
    let source = FallbackConsentSource(
        primary: ScriptedConsentSource { _ in throw ConsentError.malformedResponse("garbage") },
        fallback: ScriptedConsentSource { _ in
            Issue.record("fallback must not be consulted after a protocol violation")
            return SignedConsent(keyID: "never", signature: Data(), origin: .local)
        }
    )
    await #expect(throws: ConsentError.self) {
        _ = try await source.obtainSignature(request)
    }
}

// MARK: - LocalHelper contract mapping

private func helper(respond: @escaping @Sendable (String, [String]) -> SubprocessResult) -> (LocalHelper, FakeRunner) {
    let runner = FakeRunner(respond: respond)
    let source = LocalHelper(
        consoleUser: ConsoleUser(name: "yasyf", uid: 501),
        verifier: "/Library/PrivilegedHelperTools/cc-sudo-exec",
        runner: runner
    )
    return (source, runner)
}

@Test func localHelperReentersTheVerifierAsPromptHelperInTheConsoleSession() async throws {
    let response = try JSONEncoder().encode(ConsentSignResponse(keyID: "k", sig: Data([7]).base64EncodedString()))
    let (source, runner) = helper { _, _ in
        SubprocessResult(exitCode: 0, stdout: response, stderr: Data())
    }
    let consent = try await source.obtainSignature(request)
    #expect(consent.origin == .local)
    #expect(consent.signature == Data([7]))

    // The spawn re-enters the PINNED root verifier as prompt-helper — not
    // `sudo -u` — so the pinned cc-sudo binary becomes authkit's same-user
    // parent. authkit is never named on the command line; prompt-helper
    // re-resolves and re-pins it.
    let spawn = try #require(runner.spawns.first)
    #expect(spawn.executable == "/bin/launchctl")
    #expect(spawn.arguments == [
        "asuser", "501",
        "/Library/PrivilegedHelperTools/cc-sudo-exec", "prompt-helper", "--uid", "501",
        "--", "consent-sign",
    ])
    #expect(!spawn.arguments.contains("/usr/bin/sudo"))

    let sent = try JSONDecoder().decode(ConsentSignRequest.self, from: #require(spawn.stdin))
    #expect(sent.argv == request.argv)
    #expect(Data(base64Encoded: sent.nonce) == request.nonce)
    #expect(sent.requestedFrom == nil)
}

@Test(arguments: [
    (Int32(1), ConsentError.denied),
    (Int32(2), ConsentError.unavailable("nope")),
    (Int32(3), ConsentError.screenLocked("nope")),
])
func localHelperMapsContractExitCodes(code: Int32, expected: ConsentError) async throws {
    let (source, _) = helper { _, _ in .exit(code, stderr: "nope") }
    do {
        _ = try await source.obtainSignature(request)
        Issue.record("expected a ConsentError for exit \(code)")
    } catch let error as ConsentError {
        switch (error, expected) {
        case (.denied, .denied), (.unavailable, .unavailable), (.screenLocked, .screenLocked):
            break
        default:
            Issue.record("exit \(code) mapped to \(error), want \(expected)")
        }
    }
}

@Test func localHelperGarbageStdoutIsMalformed() async throws {
    let (source, _) = helper { _, _ in .exit(0, stdout: "not json") }
    await #expect(throws: ConsentError.self) {
        _ = try await source.obtainSignature(request)
    }
}
