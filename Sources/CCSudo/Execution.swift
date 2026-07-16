import Foundation

/// Replaces this process with the approved argv — stdio inherited, exit status
/// the command's own. argv[0] resolves through PATH like sudo would; the argv
/// TEXT is byte-identical to what was hashed, displayed, and signed.
public enum Execution {
    public enum ExecutionError: Error, Sendable {
        case execFailed(command: String, errno: Int32)
    }

    public static func replaceProcess(argv: [String]) throws -> Never {
        var cArgv: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) }
        cArgv.append(nil)
        execvp(argv[0], cArgv)
        let savedErrno = errno
        for pointer in cArgv {
            free(pointer)
        }
        throw ExecutionError.execFailed(command: argv[0], errno: savedErrno)
    }
}
