import Foundation
import SystemConfiguration

/// The user owning the console GUI session — where `launchctl asuser` lands the
/// helper and its Touch ID sheet. `nil` when nobody owns the console (login
/// window, headless).
public struct ConsoleUser: Sendable, Equatable {
    public let name: String
    public let uid: uid_t

    public init(name: String, uid: uid_t) {
        self.name = name
        self.uid = uid
    }

    public static func current() -> ConsoleUser? {
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) as String? else {
            return nil
        }
        guard name != "loginwindow" else { return nil }
        return ConsoleUser(name: name, uid: uid)
    }

    /// The user's home directory, from the passwd database (never $HOME — the
    /// verifier runs under sudo with a reset environment).
    public var homeDirectory: URL? {
        guard let passwd = getpwuid(uid), let dir = passwd.pointee.pw_dir else { return nil }
        return URL(filePath: String(cString: dir), directoryHint: .isDirectory)
    }
}
