import AuthKit
import Darwin
import Foundation
import os

/// The root-only privilege-drop shim that makes the PINNED cc-sudo verifier
/// authkit's direct, same-user parent.
///
/// authkit's `CallerCheck` resolves its invoker from `getppid()`'s audit token
/// (`task_name_for_pid` + `TASK_AUDIT_TOKEN`) and requires a Developer-ID,
/// Team-pinned binary whose identifier is one of the fleet callers. That
/// resolution only works when the pinned caller is the DIRECT, SAME-USER
/// parent — which holds for cookiesync and synckit, who spawn authkit directly
/// as the user. cc-sudo's console transport could not: `launchctl asuser <uid>
/// sudo -u #<uid> -H <helper>` interposes a ROOT-owned `sudo` monitor as the
/// helper's parent, and a process that has dropped to the console user cannot
/// read a root parent's task port (`task_name_for_pid` returns `KERN_FAILURE`),
/// and `sudo` is not a pinned identifier anyway. Install keygen and every run
/// failed caller validation (exit 4) before any sheet.
///
/// This shim runs as root inside the console user's GUI bootstrap (placed there
/// by `launchctl asuser`), drops to the console user ITSELF — supplementary
/// groups, gid, then uid, verified non-regainable — and spawns the root-owned
/// staged authkit as a direct child with inherited stdio. authkit's parent is
/// then this cc-sudo verifier copy running as the console user: same-user and a
/// pinned identifier, so `CallerCheck` validates with nothing weakened. The
/// escalation boundary is unchanged — the root path-pin on the staged authkit,
/// the Secure-Enclave key's user-presence ACL, and the root-generated nonce.
public enum PrivilegedSpawn {
    public enum SpawnError: Error, Sendable, Equatable {
        case notRoot(euid: uid_t)
        case targetIsRoot
        case unknownUser(uid: uid_t)
        case missingSubcommand
        case disallowedSubcommand(String)
        case privilegeDropFailed(step: String, code: Int32)
        case dropNotIrreversible
        case spawnFailed(path: String, code: Int32)
        case waitFailed(code: Int32)
    }

    /// The hidden cc-sudo subcommand the root verifier re-enters as to become
    /// authkit's pinned parent.
    public static let subcommandName = "prompt-helper"

    /// The ONLY authkit subcommands cc-sudo drives: `consent-sign` (the run
    /// consent flow), `keygen` (install enrollment), and `consent` (the doctor
    /// prompt-path probe). The shim refuses anything else, so even a caller that
    /// reached `prompt-helper` cannot proxy authkit's `vault-*`/`cache-*`
    /// secret-extraction surface with a forged prompt — a second line of defense
    /// behind the `exec`-only sudoers rule.
    static let allowedAuthkitSubcommands: Set<String> = ["consent-sign", "keygen", "consent"]

    /// Exit code for the shim's OWN failures — outside authkit's 0–4 contract,
    /// so a drop/spawn failure surfaces upstream as a loud malformed-response
    /// error instead of masquerading as a denial (1) or an unavailable fallback
    /// (2/3). A successful spawn propagates authkit's own exit code verbatim.
    public static let internalFailureExitCode: Int32 = 71

    static let launchctl = "/bin/launchctl"

    /// Builds the `launchctl asuser` invocation the ROOT verifier uses to reach
    /// `prompt-helper` in the console user's GUI bootstrap. authkit is resolved
    /// and re-pinned INSIDE `prompt-helper` — never named on the command line —
    /// so the trust anchor cannot be steered by the argv, exactly as the runtime
    /// verifier never honors `AUTHKIT_HELPER`.
    public static func launchctlInvocation(
        verifier: String,
        consoleUID: uid_t,
        authkitSubcommand: String,
        reason: String? = nil
    ) -> (executable: String, arguments: [String]) {
        var arguments = [
            "asuser", String(consoleUID),
            verifier, subcommandName, "--uid", String(consoleUID),
        ]
        if let reason {
            arguments += ["--reason", reason]
        }
        arguments += ["--", authkitSubcommand]
        return (launchctl, arguments)
    }

    /// The scrubbed environment the dropped authkit runs with — never the root
    /// verifier's ambient environment. Mirrors `sudo -H`: the console user's
    /// HOME and identity and a fixed system PATH, plus `AUTHKIT_REASON` only
    /// when a verdict or vault subcommand needs it (`consent-sign` and `keygen`
    /// derive their reason from the signed argv, never the environment).
    static func childEnvironment(home: String, userName: String, reason: String?) -> [String: String] {
        var environment = [
            "HOME": home,
            "USER": userName,
            "LOGNAME": userName,
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        ]
        if let reason {
            environment[CLI.reasonEnvironmentVariable] = reason
        }
        return environment
    }

    /// Runs the shim: assert root, drop to the console user, re-pin the staged
    /// authkit, and spawn it as a direct same-user child with inherited stdio.
    /// Returns authkit's own exit code (propagated verbatim) so the upstream
    /// `ConsentSource` maps the 0–4 contract exactly as before. Every failure
    /// throws — there is no path that proceeds with privileges half-dropped.
    public static func run(targetUID: uid_t, authkitArguments: [String], reason: String?) throws -> Int32 {
        let euid = geteuid()
        guard euid == 0 else { throw SpawnError.notRoot(euid: euid) }
        guard let subcommand = authkitArguments.first else { throw SpawnError.missingSubcommand }
        guard allowedAuthkitSubcommands.contains(subcommand) else {
            throw SpawnError.disallowedSubcommand(subcommand)
        }
        guard targetUID != 0 else { throw SpawnError.targetIsRoot }
        guard let passwd = getpwuid(targetUID) else { throw SpawnError.unknownUser(uid: targetUID) }
        let gid = passwd.pointee.pw_gid
        let userName = String(cString: passwd.pointee.pw_name)
        let home = String(cString: passwd.pointee.pw_dir)

        try dropPrivileges(toUID: targetUID, gid: gid, userName: userName)

        // Re-pin the ROOT-OWNED staged authkit under the dropped credentials
        // that will exec it. The staging directory is unwritable to this user,
        // so the bytes validated are the bytes spawned.
        let authkit = try HelperTrust.stagedHelperBinary()
        let environment = childEnvironment(home: home, userName: userName, reason: reason)
        return try spawnAndWait(
            executable: authkit.path(),
            arguments: authkitArguments,
            environment: environment
        )
    }

    /// The irreversible drop: supplementary groups and gid BEFORE uid (dropping
    /// uid first forfeits the privilege to set the others), then a verification
    /// that root cannot be regained before anything is exec'd.
    static func dropPrivileges(toUID uid: uid_t, gid: gid_t, userName: String) throws {
        let groupsResult = userName.withCString { initgroups($0, Int32(bitPattern: gid)) }
        guard groupsResult == 0 else {
            throw SpawnError.privilegeDropFailed(step: "initgroups", code: errno)
        }
        guard setgid(gid) == 0 else { throw SpawnError.privilegeDropFailed(step: "setgid", code: errno) }
        guard setuid(uid) == 0 else { throw SpawnError.privilegeDropFailed(step: "setuid", code: errno) }
        guard getuid() == uid, geteuid() == uid, getgid() == gid, getegid() == gid else {
            throw SpawnError.dropNotIrreversible
        }
        // The saved-set uid is now the console user's, so regaining root must
        // fail. If it somehow succeeds, abort rather than exec with latent root.
        guard setuid(0) == -1 else { throw SpawnError.dropNotIrreversible }
    }

    static func spawnAndWait(
        executable: String,
        arguments: [String],
        environment: [String: String]
    ) throws -> Int32 {
        var cArgv: [UnsafeMutablePointer<CChar>?] = ([executable] + arguments).map { strdup($0) }
        cArgv.append(nil)
        var cEnv: [UnsafeMutablePointer<CChar>?] = environment.map { strdup("\($0.key)=\($0.value)") }
        cEnv.append(nil)
        defer {
            for pointer in cArgv {
                free(pointer)
            }
            for pointer in cEnv {
                free(pointer)
            }
        }

        var pid: pid_t = 0
        let spawnResult = posix_spawn(&pid, executable, nil, nil, cArgv, cEnv)
        guard spawnResult == 0 else { throw SpawnError.spawnFailed(path: executable, code: spawnResult) }

        var status: Int32 = 0
        while waitpid(pid, &status, 0) == -1 {
            guard errno == EINTR else { throw SpawnError.waitFailed(code: errno) }
        }
        return exitCode(forWaitStatus: status)
    }

    /// Maps a `waitpid` status to a process exit code: a normal exit returns its
    /// code, a signal maps to 128 + signal (the shell convention).
    static func exitCode(forWaitStatus status: Int32) -> Int32 {
        if status & 0x7F == 0 {
            return (status >> 8) & 0xFF
        }
        return 128 + (status & 0x7F)
    }
}
