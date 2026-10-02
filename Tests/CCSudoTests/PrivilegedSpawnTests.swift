import AuthKit
@testable import CCSudo
import Darwin
import Foundation
import Testing

// MARK: - launchctl invocation

@Test func launchctlInvocationReentersTheVerifierAsPromptHelper() {
    let invocation = PrivilegedSpawn.launchctlInvocation(
        verifier: "/Library/PrivilegedHelperTools/cc-sudo-exec",
        consoleUID: 501,
        authkitSubcommand: "consent-sign"
    )
    #expect(invocation.executable == "/bin/launchctl")
    #expect(invocation.arguments == [
        "asuser", "501",
        "/Library/PrivilegedHelperTools/cc-sudo-exec", "prompt-helper", "--uid", "501",
        "--", "consent-sign",
    ])
    // The sudo hop that broke the caller pin is gone, and authkit is never
    // named on the command line — prompt-helper re-resolves and re-pins it.
    #expect(!invocation.arguments.contains("/usr/bin/sudo"))
    #expect(!invocation.arguments.contains(where: { $0.contains("authkit") }))
}

@Test func launchctlInvocationThreadsReasonForVerdictSubcommands() {
    let invocation = PrivilegedSpawn.launchctlInvocation(
        verifier: "/v",
        consoleUID: 502,
        authkitSubcommand: "consent",
        reason: "cc-sudo doctor: prompt-path probe"
    )
    #expect(invocation.arguments == [
        "asuser", "502",
        "/v", "prompt-helper", "--uid", "502",
        "--reason", "cc-sudo doctor: prompt-path probe",
        "--", "consent",
    ])
}

// MARK: - child environment scrubbing

@Test func childEnvironmentIsScrubbedToTheConsoleUser() {
    let environment = PrivilegedSpawn.childEnvironment(home: "/Users/yasyf", userName: "yasyf", reason: nil)
    #expect(environment["HOME"] == "/Users/yasyf")
    #expect(environment["USER"] == "yasyf")
    #expect(environment["LOGNAME"] == "yasyf")
    #expect(environment["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
    // consent-sign and keygen derive their reason from the signed argv, never
    // the environment, so no reason is injected when none is asked for.
    #expect(environment[CLI.reasonEnvironmentVariable] == nil)
}

@Test func childEnvironmentCarriesReasonOnlyWhenAsked() {
    let environment = PrivilegedSpawn.childEnvironment(home: "/Users/yasyf", userName: "yasyf", reason: "why")
    #expect(environment[CLI.reasonEnvironmentVariable] == "why")
}

// MARK: - wait-status mapping

@Test(arguments: [
    (Int32(0), Int32(0)),
    (Int32(1) << 8, Int32(1)),
    (Int32(4) << 8, Int32(4)),
    (Int32(103) << 8, Int32(103)),
])
func exitCodePropagatesANormalExitVerbatim(status: Int32, expected: Int32) {
    #expect(PrivilegedSpawn.exitCode(forWaitStatus: status) == expected)
}

@Test func exitCodeMapsASignalToTheShellConvention() {
    // Low 7 bits carry the terminating signal; SIGKILL (9) -> 128 + 9.
    #expect(PrivilegedSpawn.exitCode(forWaitStatus: SIGKILL) == 128 + SIGKILL)
}

// MARK: - fail-closed gating

@Test func runRefusesWhenNotRoot() {
    // The test process is not root, so the euid gate fires before any drop or
    // spawn — exactly what blocks a user-level `cc-sudo prompt-helper` from
    // making cc-sudo authkit's parent and defeating the caller pin.
    guard geteuid() != 0 else { return }
    do {
        _ = try PrivilegedSpawn.run(targetUID: 501, authkitArguments: ["keygen"], reason: nil)
        Issue.record("prompt-helper must refuse a non-root invoker")
    } catch let error as PrivilegedSpawn.SpawnError {
        #expect(error == .notRoot(euid: geteuid()))
    } catch {
        Issue.record("unexpected error \(error)")
    }
}

@Test func runNeverDropsToRoot() {
    // targetUID 0 is not a privilege drop; it must be refused. When not root the
    // euid gate wins first, but either way `run` throws rather than spawning
    // authkit as root.
    #expect(throws: PrivilegedSpawn.SpawnError.self) {
        _ = try PrivilegedSpawn.run(targetUID: 0, authkitArguments: ["keygen"], reason: nil)
    }
}

// MARK: - authkit subcommand allowlist

@Test func allowlistCoversExactlyCcSudosThreeNeeds() {
    #expect(PrivilegedSpawn.allowedAuthkitSubcommands == ["consent-sign", "keygen", "consent"])
}

@Test func allowlistExcludesTheSecretExtractionSurface() {
    // vault-* and cache-* return key material; prompt-helper must never proxy
    // them, so admin-session code cannot extract secrets with a forged prompt.
    let forbidden = ["vault-retrieve", "vault-retrieve-biometric", "vault-batch-retrieve", "cache-unwrap", "cache-wrap"]
    for subcommand in forbidden {
        #expect(!PrivilegedSpawn.allowedAuthkitSubcommands.contains(subcommand))
    }
}
