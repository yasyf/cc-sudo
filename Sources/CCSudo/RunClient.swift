import Foundation
import os

/// The unprivileged side of a run: both `cc-sudo run` and the MCP tool drive
/// the SAME flow — `sudo -n <root-owned verifier> exec --client-version <v>
/// -- <argv>` — so consent enforcement lives only behind the sudoers boundary.
public enum RunClient {
    public static let verifierPath = "/Library/PrivilegedHelperTools/cc-sudo-exec"

    /// A captured (non-exec) run, for the MCP surface.
    public struct CapturedRun: Sendable {
        public let stdout: String
        public let stderr: String
        public let exitCode: Int32
        public let verdict: String
    }

    public enum RunError: Error, Sendable {
        case timedOut(afterMS: Int)
    }

    /// The full argv of the privileged invocation.
    public static func invocation(argv: [String], clientVersion: String = Version.current) -> [String] {
        ["/usr/bin/sudo", "-n", verifierPath, "exec", "--client-version", clientVersion, "--"] + argv
    }

    /// Reads the installed verifier's version without sudo, before any run.
    /// Returns a warning when the verifier is behind but usable; throws when
    /// the two cannot work together, so the failure names its fix before sudo.
    static func checkVerifier(
        runner: any ProcessRunner = LiveProcessRunner(),
        clientVersion: String = Version.current
    ) async throws -> String? {
        guard let installed = await installedVerifierVersion(runner: runner) else {
            throw VersionSkewError(clientVersion: clientVersion, verifierVersion: nil)
        }
        let compatibility = VerifierCompatibility(client: clientVersion, verifier: installed)
        guard compatibility.allowsRun else {
            throw VersionSkewError(clientVersion: clientVersion, verifierVersion: installed)
        }
        return compatibility == .verifierBehind ? behindMessage(installed: installed, client: clientVersion) : nil
    }

    static func installedVerifierVersion(runner: any ProcessRunner) async -> String? {
        guard let result = try? await runner.run(
            executable: verifierPath, arguments: ["--version"], stdin: nil, environment: nil
        ), result.exitCode == 0 else {
            return nil
        }
        return result.stdout.utf8Lossy.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func behindMessage(installed: String, client: String) -> String {
        "verifier \(installed) is behind this CLI (\(client)); commands still run, " +
            "but run 'sudo cc-sudo install' to update it"
    }

    /// Replaces this process with the privileged invocation: stdio inherited,
    /// the command's (or the verifier's documented) exit status passes through.
    /// `argv[0]` is resolved to an absolute path against the caller's PATH here,
    /// on the unprivileged side, so the signed subject binds the absolute binary
    /// and root never runs a PATH search.
    public static func exec(argv: [String]) async throws -> Never {
        let resolved = try PathResolver.resolve(argv: argv)
        if let warning = try await checkVerifier() {
            FileHandle.standardError.write(Data("cc-sudo: \(warning)\n".utf8))
        }
        try Execution.replaceProcess(argv: invocation(argv: resolved))
    }

    /// Runs the privileged invocation capturing output, for MCP. `timeoutMS`
    /// bounds the whole run including the human's tap; nil waits the sheet out.
    public static func capture(
        argv: [String],
        cwd: String? = nil,
        timeoutMS: Int? = nil,
        preflightRunner: any ProcessRunner = LiveProcessRunner()
    ) async throws -> CapturedRun {
        let resolved = try PathResolver.resolve(
            argv: argv,
            currentDirectory: cwd ?? FileManager.default.currentDirectoryPath
        )
        let warning: String?
        do {
            warning = try await checkVerifier(runner: preflightRunner)
        } catch let skew as VersionSkewError {
            let code = ExitStatus.versionSkew.rawValue
            return CapturedRun(
                stdout: "",
                stderr: "cc-sudo: \(skew.message)\n",
                exitCode: code,
                verdict: ExitStatus.verdict(forExitCode: code)
            )
        }
        let run = try await captureInvocation(invocation(argv: resolved), cwd: cwd, timeoutMS: timeoutMS)
        return CapturedRun(
            stdout: run.stdout,
            stderr: (warning.map { "cc-sudo: \($0)\n" } ?? "") + run.stderr,
            exitCode: run.exitCode,
            verdict: run.verdict
        )
    }

    private static func captureInvocation(
        _ full: [String],
        cwd: String?,
        timeoutMS: Int?
    ) async throws -> CapturedRun {
        let process = Process()
        process.executableURL = URL(filePath: full[0])
        process.arguments = Array(full.dropFirst())
        if let cwd {
            process.currentDirectoryURL = URL(filePath: cwd, directoryHint: .isDirectory)
        }

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        process.standardInput = FileHandle.nullDevice
        try process.run()

        async let stdoutData = Task.detached { stdoutPipe.fileHandleForReading.readDataToEndOfFile() }.value
        async let stderrData = Task.detached { stderrPipe.fileHandleForReading.readDataToEndOfFile() }.value

        let timedOut = OSAllocatedUnfairLock(initialState: false)
        if let timeoutMS {
            let deadline = Task {
                try await Task.sleep(for: .milliseconds(timeoutMS))
                if process.isRunning {
                    timedOut.withLock { $0 = true }
                    process.terminate()
                }
            }
            await Task.detached { process.waitUntilExit() }.value
            deadline.cancel()
        } else {
            await Task.detached { process.waitUntilExit() }.value
        }

        let stdout = await stdoutData
        let stderr = await stderrData
        let code = process.terminationStatus
        if timedOut.withLock({ $0 }), let timeoutMS {
            throw RunError.timedOut(afterMS: timeoutMS)
        }
        return CapturedRun(
            stdout: stdout.utf8Lossy,
            stderr: stderr.utf8Lossy,
            exitCode: code,
            verdict: ExitStatus.verdict(forExitCode: code)
        )
    }
}
