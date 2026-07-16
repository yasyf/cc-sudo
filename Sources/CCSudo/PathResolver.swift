import Foundation

/// Resolves `argv[0]` to an ABSOLUTE path on the UNPRIVILEGED side of a run,
/// before the request is composed, hashed, displayed, and signed — so what the
/// human approves and what root executes are the same binary, with no PATH
/// search ever running as root. An already-absolute `argv[0]` is unchanged; a
/// bare name is searched on the caller's PATH; anything unresolvable is a clear
/// error rather than a silent substitution.
public enum PathResolver {
    public enum ResolveError: Error, Sendable {
        case notFound(command: String, searchedPATH: String)
        case notExecutable(path: String)
        case emptyArgv
    }

    /// Returns `argv` with `argv[0]` replaced by its absolute resolution.
    public static func resolve(
        argv: [String],
        environment: [String: String] = ProcessInfo.processInfo.environment,
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) throws -> [String] {
        guard let command = argv.first else { throw ResolveError.emptyArgv }
        let absolute = try resolveExecutable(
            command,
            environment: environment,
            currentDirectory: currentDirectory,
            fileManager: fileManager
        )
        return [absolute] + argv.dropFirst()
    }

    /// Resolves one command name to an absolute executable path. A name
    /// containing "/" is taken as a path (absolute kept, relative anchored to
    /// `currentDirectory`); a bare name is searched across PATH. The chosen
    /// candidate must be an executable file.
    public static func resolveExecutable(
        _ command: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        currentDirectory: String = FileManager.default.currentDirectoryPath,
        fileManager: FileManager = .default
    ) throws -> String {
        let searchPath = environment["PATH"] ?? ""
        if command.contains("/") {
            let url = URL(filePath: command, relativeTo: URL(filePath: currentDirectory, directoryHint: .isDirectory))
            let absolute = url.standardizedFileURL.path()
            guard fileManager.isExecutableFile(atPath: absolute) else {
                throw ResolveError.notExecutable(path: absolute)
            }
            return absolute
        }
        for directory in searchPath.split(separator: ":", omittingEmptySubsequences: true) {
            let candidate = URL(filePath: String(directory), directoryHint: .isDirectory)
                .appending(component: command)
                .standardizedFileURL.path()
            if fileManager.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        throw ResolveError.notFound(command: command, searchedPATH: searchPath)
    }
}
