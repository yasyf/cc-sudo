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

    /// Replaces this process with the privileged invocation: stdio inherited,
    /// the command's (or the verifier's documented) exit status passes through.
    public static func exec(argv: [String]) throws -> Never {
        try Execution.replaceProcess(argv: invocation(argv: argv))
    }

    /// Runs the privileged invocation capturing output, for MCP. `timeoutMS`
    /// bounds the whole run including the human's tap; nil waits the sheet out.
    public static func capture(
        argv: [String],
        cwd: String? = nil,
        timeoutMS: Int? = nil
    ) async throws -> CapturedRun {
        let full = invocation(argv: argv)
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
