import AuthKit
import Foundation
import os

/// `cc-sudo doctor`: every trust-chain link, one check each, no mutations.
/// The default run is non-interactive; `probePrompt` additionally fires a real
/// verdict-only consent sheet through the asuser path (root + a tap) to settle
/// the one question the mechanics spike left open — whether an SSH-descended
/// sudo child can render the console sheet.
public struct Doctor: Sendable {
    public enum Status: String, Sendable {
        case pass = "ok"
        case fail = "FAIL"
        case warn
        case info
    }

    public struct CheckResult: Sendable {
        public let name: String
        public let status: Status
        public let detail: String
    }

    let runner: any ProcessRunner
    let store: TrustStore

    public init(runner: any ProcessRunner = LiveProcessRunner(), store: TrustStore = TrustStore()) {
        self.runner = runner
        self.store = store
    }

    public func checks(probePrompt: Bool = false) async -> [CheckResult] {
        var results: [CheckResult] = []
        await results.append(verifierCheck())
        await results.append(sudoersCheck())
        results.append(helperPinCheck())
        results.append(synckitCheck())
        results.append(selfKeyCheck())
        results.append(peerKeysCheck())
        results.append(originIdentityCheck())
        results.append(promptPathCheck())
        if probePrompt {
            await results.append(promptProbe())
        }
        return results
    }

    func verifierCheck() async -> CheckResult {
        let path = RunClient.verifierPath
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return CheckResult(
                name: "verifier",
                status: .fail,
                detail: "\(path) missing — run 'sudo cc-sudo install'"
            )
        }
        guard let result = try? await runner.run(
            executable: path, arguments: ["--version"], stdin: nil, environment: nil
        ), result.exitCode == 0 else {
            return CheckResult(name: "verifier", status: .fail, detail: "\(path) --version failed")
        }
        let installed = result.stdout.utf8Lossy
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard installed == Version.current else {
            return CheckResult(
                name: "verifier",
                status: .fail,
                detail: "version skew: CLI \(Version.current) vs verifier \(installed) — run 'sudo cc-sudo install'"
            )
        }
        return CheckResult(name: "verifier", status: .pass, detail: "\(path) at \(installed)")
    }

    func sudoersCheck() async -> CheckResult {
        let path = Installer.sudoersPath
        guard FileManager.default.fileExists(atPath: path) else {
            return CheckResult(name: "sudoers", status: .fail, detail: "\(path) missing — run 'sudo cc-sudo install'")
        }
        guard geteuid() == 0 else {
            return CheckResult(
                name: "sudoers", status: .info, detail: "\(path) present (run doctor with sudo to validate)"
            )
        }
        guard let result = try? await runner.run(
            executable: Installer.visudo, arguments: ["-c", "-f", path], stdin: nil, environment: nil
        ), result.exitCode == 0 else {
            return CheckResult(name: "sudoers", status: .fail, detail: "visudo rejects \(path)")
        }
        return CheckResult(name: "sudoers", status: .pass, detail: "\(path) valid")
    }

    func helperPinCheck() -> CheckResult {
        do {
            let binary = try HelperTrust.stagedHelperBinary()
            return CheckResult(name: "authkit pin", status: .pass, detail: binary.path())
        } catch {
            return CheckResult(name: "authkit pin", status: .fail, detail: String(describing: error))
        }
    }

    func synckitCheck() -> CheckResult {
        guard let home = PromptStrategy.socketHome(
            console: ConsoleUser.current(),
            invokerUID: PromptStrategy.sudoInvokerUID() ?? getuid()
        ) else {
            return CheckResult(name: "synckitd", status: .warn, detail: "no user to resolve a socket for")
        }
        let path = SynckitClient.socketPath(home: home)
        let reachable = SynckitClient(socketPath: path).probe()
        return CheckResult(
            name: "synckitd",
            status: reachable ? .pass : .warn,
            detail: reachable ? path : "\(path) unreachable — routed/locked-Mac approvals unavailable"
        )
    }

    func selfKeyCheck() -> CheckResult {
        do {
            let key = try store.selfKey()
            return CheckResult(name: "self key", status: .pass, detail: Attestation.keyID(publicKey: key))
        } catch {
            return CheckResult(name: "self key", status: .fail, detail: String(describing: error))
        }
    }

    func peerKeysCheck() -> CheckResult {
        let peers = store.enrolledPeers()
        guard !peers.isEmpty else {
            return CheckResult(name: "peer keys", status: .info, detail: "none enrolled ('cc-sudo trust <peer>')")
        }
        var details: [String] = []
        var failed = false
        for peer in peers {
            do {
                let key = try store.peerKey(host: peer)
                details.append("\(peer)=\(Attestation.keyID(publicKey: key).prefix(12))…")
            } catch {
                failed = true
                details.append("\(peer): \(error)")
            }
        }
        return CheckResult(name: "peer keys", status: failed ? .fail : .pass, detail: details.joined(separator: ", "))
    }

    func originIdentityCheck() -> CheckResult {
        do {
            let identity = try OriginIdentity.read()
            return CheckResult(
                name: "origin identity",
                status: .pass,
                detail: "\(identity) (must match synckitd's mesh self name)"
            )
        } catch {
            return CheckResult(
                name: "origin identity",
                status: store.enrolledPeers().isEmpty ? .info : .fail,
                detail: "\(OriginIdentity.path) unconfigured — routed approvals cannot verify"
            )
        }
    }

    func promptPathCheck() -> CheckResult {
        let console = ConsoleUser.current()
        let invoker = PromptStrategy.sudoInvokerUID() ?? getuid()
        switch PromptStrategy.select(console: console, invokerUID: invoker) {
        case let .localThenSynckit(user):
            return CheckResult(
                name: "prompt path",
                status: .pass,
                detail: "local helper via launchctl asuser \(user.uid) (\(user.name)), synckitd fallback"
            )
        case .synckitOnly:
            let reason = console == nil
                ? "no console user"
                : "invoker uid \(invoker) is not the console user (\(console?.uid ?? 0))"
            return CheckResult(name: "prompt path", status: .warn, detail: "synckitd only — \(reason)")
        }
    }

    /// Fires a REAL verdict-only sheet through the asuser path. Requires root
    /// and a human tap; maps the helper's contract exit code to a result.
    func promptProbe() async -> CheckResult {
        guard geteuid() == 0 else {
            return CheckResult(
                name: "prompt probe", status: .warn, detail: "requires root: sudo cc-sudo doctor --probe-prompt"
            )
        }
        guard let console = ConsoleUser.current() else {
            return CheckResult(name: "prompt probe", status: .warn, detail: "no console user to prompt")
        }
        let helper: URL
        do {
            helper = try HelperTrust.stagedHelperBinary()
        } catch {
            return CheckResult(name: "prompt probe", status: .fail, detail: "authkit pin failed: \(error)")
        }
        // The reason rides an explicit /usr/bin/env hop: sudo's env_reset would
        // strip a variable set on the outer launchctl process.
        guard let result = try? await runner.run(
            executable: LocalHelper.launchctl,
            arguments: [
                "asuser", String(console.uid),
                LocalHelper.sudo, "-u", "#\(console.uid)", "-H",
                "/usr/bin/env", "\(CLI.reasonEnvironmentVariable)=cc-sudo doctor: prompt-path probe",
                helper.path(), "consent",
            ],
            stdin: nil,
            environment: nil
        ) else {
            return CheckResult(name: "prompt probe", status: .fail, detail: "helper spawn failed")
        }
        switch result.exitCode {
        case 0: return CheckResult(name: "prompt probe", status: .pass, detail: "asuser sheet rendered and approved")
        case 1: return CheckResult(name: "prompt probe", status: .pass, detail: "asuser sheet rendered (denied)")
        case 2: return CheckResult(
                name: "prompt probe", status: .warn, detail: "unavailable — runtime will use the synckitd path"
            )
        case 3: return CheckResult(name: "prompt probe", status: .warn, detail: "screen locked — try unlocked")
        default: return CheckResult(name: "prompt probe", status: .fail, detail: "helper exited \(result.exitCode)")
        }
    }
}
