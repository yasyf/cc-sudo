import Foundation

/// Replaces this process with the approved argv — stdio inherited, exit status
/// the command's own. Uses `execv` (NOT `execvp`): no PATH search ever runs as
/// root, so the resolved absolute binary is exactly the one that was hashed,
/// displayed, and signed. A non-absolute `argv[0]` is refused fail-closed — the
/// unprivileged run side resolves it to an absolute path before signing.
public enum Execution {
    public enum ExecutionError: Error, Sendable {
        case execFailed(command: String, errno: Int32)
        case nonAbsoluteExecutable(command: String)
    }

    public static func replaceProcess(argv: [String]) throws -> Never {
        guard let command = argv.first, command.hasPrefix("/") else {
            throw ExecutionError.nonAbsoluteExecutable(command: argv.first ?? "")
        }
        var cArgv: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) }
        cArgv.append(nil)
        execv(command, cArgv)
        let savedErrno = errno
        for pointer in cArgv {
            free(pointer)
        }
        throw ExecutionError.execFailed(command: command, errno: savedErrno)
    }
}
