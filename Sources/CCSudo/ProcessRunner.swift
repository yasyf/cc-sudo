import Foundation

/// A captured subprocess outcome.
public struct SubprocessResult: Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// The subprocess boundary: tests fake it so no real launchctl, sudo, ssh, or
/// helper ever runs in CI.
public protocol ProcessRunner: Sendable {
    func run(
        executable: String,
        arguments: [String],
        stdin: Data?,
        environment: [String: String]?
    ) async throws -> SubprocessResult
}

/// Foundation.Process-backed runner used in production.
public struct LiveProcessRunner: ProcessRunner {
    public enum SpawnError: Error, Sendable {
        case launchFailed(executable: String, detail: String)
    }

    public init() {}

    public func run(
        executable: String,
        arguments: [String],
        stdin: Data?,
        environment: [String: String]?
    ) async throws -> SubprocessResult {
        let process = Process()
        process.executableURL = URL(filePath: executable)
        process.arguments = arguments
        if let environment {
            process.environment = environment
        }

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            throw SpawnError.launchFailed(executable: executable, detail: error.localizedDescription)
        }

        if let stdin {
            try stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
        }
        try stdinPipe.fileHandleForWriting.close()

        // Drain both pipes concurrently BEFORE waiting: a child that fills a
        // pipe buffer while nobody reads would deadlock against waitUntilExit.
        async let stdoutData = readToEnd(stdoutPipe)
        async let stderrData = readToEnd(stderrPipe)
        let stdout = try await stdoutData
        let stderr = try await stderrData

        await Task.detached { process.waitUntilExit() }.value
        return SubprocessResult(exitCode: process.terminationStatus, stdout: stdout, stderr: stderr)
    }

    private func readToEnd(_ pipe: Pipe) async throws -> Data {
        try await Task.detached {
            try pipe.fileHandleForReading.readToEnd() ?? Data()
        }.value
    }
}
