import AuthKit
import Foundation
import os

/// Sets up (and tears down) the privileged boundary. Everything it writes is
/// root-owned at STABLE paths — never a Homebrew Cellar/Caskroom path, which
/// are user-writable and would be instant escalation behind the NOPASSWD rule.
/// A brew upgrade therefore requires re-running `cc-sudo install`.
public struct Installer: Sendable {
    public enum InstallError: Error, Sendable {
        case notRoot
        case sudoersRejected(detail: String)
        case keygenFailed(exitCode: Int32, stderr: String)
        case malformedKeygenOutput(String)
        case noConsoleUser
    }

    public static let verifierDirectory = "/Library/PrivilegedHelperTools"
    public static let verifierPath = RunClient.verifierPath
    public static let sudoersPath = "/etc/sudoers.d/cc-sudo"
    public static let sudoersRule = "%admin ALL=(root) NOPASSWD: \(RunClient.verifierPath)\n"
    static let visudo = "/usr/sbin/visudo"

    let runner: any ProcessRunner
    /// Every absolute path is re-rooted here so tests install into a temp tree.
    let root: URL
    let euid: @Sendable () -> uid_t

    public init(
        runner: any ProcessRunner = LiveProcessRunner(),
        root: URL = URL(filePath: "/", directoryHint: .isDirectory),
        euid: @escaping @Sendable () -> uid_t = { geteuid() }
    ) {
        self.runner = runner
        self.root = root
        self.euid = euid
    }

    /// The full install: verify authkit's pin, copy the running binary to the
    /// root-owned verifier path, write + validate the sudoers rule, generate
    /// the user's SE key through the pinned helper, and enroll its public key.
    /// Requires root (`sudo cc-sudo install`); the SE keygen drops back to the
    /// console user, whose key it is.
    public func install(
        sourceExecutable: URL,
        originIdentity: String,
        pinnedHelper: URL,
        console: ConsoleUser
    ) async throws -> String {
        guard euid() == 0 else { throw InstallError.notRoot }
        try installVerifier(sourceExecutable: sourceExecutable)
        try await installSudoers()
        let keyID = try await enrollSelfKey(pinnedHelper: pinnedHelper, console: console)
        try writeRootFile(
            at: rooted(OriginIdentity.path),
            contents: Data((originIdentity + "\n").utf8),
            mode: 0o644
        )
        Logger.installer.info(
            "installed verifier \(Version.current, privacy: .public), enrolled key \(keyID, privacy: .public)"
        )
        return keyID
    }

    /// Removes the sudoers rule, the root-owned verifier, and the trust store.
    /// The authkit cask and the user's SE key are authkit's to manage.
    public func uninstall() throws {
        guard euid() == 0 else { throw InstallError.notRoot }
        let fileManager = FileManager.default
        for path in [Self.sudoersPath, Self.verifierPath, "/etc/cc-sudo"] {
            let url = rooted(path)
            if fileManager.fileExists(atPath: url.path()) {
                try fileManager.removeItem(at: url)
            }
        }
    }

    func installVerifier(sourceExecutable: URL) throws {
        let fileManager = FileManager.default
        let directory = rooted(Self.verifierDirectory)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: attributes(mode: 0o755)
        )
        let destination = rooted(Self.verifierPath)
        let staging = directory.appending(component: "cc-sudo-exec.installing")
        if fileManager.fileExists(atPath: staging.path()) {
            try fileManager.removeItem(at: staging)
        }
        try fileManager.copyItem(at: sourceExecutable, to: staging)
        try fileManager.setAttributes(attributes(mode: 0o755), ofItemAtPath: staging.path())
        _ = try fileManager.replaceItemAt(destination, withItemAt: staging)
    }

    func installSudoers() async throws {
        let staging = rooted("/etc/sudoers.d/.cc-sudo.installing")
        try writeRootFile(at: staging, contents: Data(Self.sudoersRule.utf8), mode: 0o440)
        let check = try await runner.run(
            executable: Self.visudo,
            arguments: ["-c", "-f", staging.path()],
            stdin: nil,
            environment: nil
        )
        guard check.exitCode == 0 else {
            try? FileManager.default.removeItem(at: staging)
            throw InstallError.sudoersRejected(detail: check.stderr.utf8Lossy)
        }
        _ = try FileManager.default.replaceItemAt(rooted(Self.sudoersPath), withItemAt: staging)
    }

    func enrollSelfKey(pinnedHelper: URL, console: ConsoleUser) async throws -> String {
        let result = try await runner.run(
            executable: LocalHelper.launchctl,
            arguments: [
                "asuser", String(console.uid),
                LocalHelper.sudo, "-u", "#\(console.uid)", "-H",
                pinnedHelper.path(), "keygen",
            ],
            stdin: nil,
            environment: nil
        )
        guard result.exitCode == 0 else {
            throw InstallError.keygenFailed(
                exitCode: result.exitCode,
                stderr: result.stderr.utf8Lossy
            )
        }
        guard let response = try? JSONDecoder().decode(KeygenResponse.self, from: result.stdout),
              let keyBytes = Data(base64Encoded: response.publicKey),
              (try? Attestation.publicKey(fromX963: keyBytes)) != nil
        else {
            throw InstallError.malformedKeygenOutput(result.stdout.prefix(256).utf8Lossy)
        }
        let store = TrustStore(directory: rooted(TrustStore.defaultDirectory.path()))
        try writeRootFile(at: store.selfKeyURL, contents: Data((response.publicKey + "\n").utf8), mode: 0o644)
        return response.keyID
    }

    func rooted(_ absolutePath: String) -> URL {
        root.appending(path: String(absolutePath.drop(while: { $0 == "/" })))
    }

    /// root:wheel ownership applies only when actually root — the test seam
    /// installs into a temp tree as a normal user, where chown would fail.
    func attributes(mode: Int16) -> [FileAttributeKey: Any] {
        var attributes: [FileAttributeKey: Any] = [.posixPermissions: mode]
        if geteuid() == 0 {
            attributes[.ownerAccountID] = 0
            attributes[.groupOwnerAccountID] = 0
        }
        return attributes
    }

    func writeRootFile(at url: URL, contents: Data, mode: Int16) throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: attributes(mode: 0o755)
        )
        try contents.write(to: url)
        try fileManager.setAttributes(attributes(mode: mode), ofItemAtPath: url.path())
    }
}
