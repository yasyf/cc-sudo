import AuthKit
import Darwin
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
        case stagingContainsSymlink(path: String)
        case enumerationFailed(path: String)
        case hardeningFailed(path: String)
        case untrustedAncestor(path: String)
        case verifierNotRegularFile(path: String)
    }

    public static let verifierDirectory = "/Library/PrivilegedHelperTools"
    public static let verifierPath = RunClient.verifierPath
    public static let sudoersPath = "/etc/sudoers.d/cc-sudo"
    /// NOPASSWD is scoped to the verifier's `exec` entrypoint ALONE — the one
    /// hot path `cc-sudo run` drives. The verifier itself gates `exec` with the
    /// nonce, the signature, and the tap, so `exec *` grants nothing `cc-sudo
    /// run` doesn't already. Admin-reachable root must NOT extend to the hidden
    /// `prompt-helper` shim or to `install`/`trust`/`uninstall`: those are
    /// password-gated setup, and leaving `prompt-helper` NOPASSWD-reachable
    /// would let admin-session code proxy arbitrary authkit operations with a
    /// forged prompt. `prompt-helper` is reached only by the already-root
    /// verifier, never through this rule.
    public static let sudoersRule = "%admin ALL=(root) NOPASSWD: \(RunClient.verifierPath) exec *\n"
    static let visudo = "/usr/sbin/visudo"

    let runner: any ProcessRunner
    /// Every absolute path is re-rooted here so tests install into a temp tree.
    let root: URL
    let euid: @Sendable () -> uid_t
    let validator: any CodeSignatureValidator
    /// The cc-sudo self-pin the verifier copy must satisfy before it becomes the
    /// root-owned NOPASSWD binary.
    let verifierRequirement: String
    /// The authkit reverse-pin the staged helper copy must satisfy.
    let helperRequirement: String

    public init(
        runner: any ProcessRunner = LiveProcessRunner(),
        root: URL = URL(filePath: "/", directoryHint: .isDirectory),
        euid: @escaping @Sendable () -> uid_t = { geteuid() },
        validator: any CodeSignatureValidator = LiveCodeSignatureValidator(),
        verifierRequirement: String = DesignatedRequirement.string(identifier: DesignatedRequirement.ccSudoIdentifier),
        helperRequirement: String = HelperTrust.requirementString()
    ) {
        self.runner = runner
        self.root = root
        self.euid = euid
        self.validator = validator
        self.verifierRequirement = verifierRequirement
        self.helperRequirement = helperRequirement
    }

    /// The full install: copy the running binary to the root-owned verifier
    /// path (provenance-checked against cc-sudo's own DR both before and after
    /// the copy), write + validate the sudoers rule, stage the validated authkit
    /// bundle into a root-owned directory, generate the user's SE key through
    /// the staged helper, and enroll its public key. Requires root
    /// (`sudo cc-sudo install`); the SE keygen drops back to the console user,
    /// whose key it is.
    ///
    /// `helperBundle` is the Caskroom authkit.app the caller has already located
    /// and validated; the installer re-validates the staged copy before use.
    public func install(
        sourceExecutable: URL,
        originIdentity: String,
        helperBundle: URL,
        console: ConsoleUser
    ) async throws -> String {
        guard euid() == 0 else { throw InstallError.notRoot }
        try installVerifier(sourceExecutable: sourceExecutable)
        try await installSudoers()
        try stageHelperBundle(from: helperBundle)
        let keyID = try await enrollSelfKey(console: console)
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

    /// Installs `sourceExecutable` as the NOPASSWD verifier: validate, check
    /// ancestors, stage a regular file in a private 0700 dir, harden, re-validate
    /// the staged bytes, promote atomically.
    func installVerifier(sourceExecutable: URL) throws {
        let fileManager = FileManager.default
        let resolved = sourceExecutable.resolvingSymlinksInPath()
        try validator.validate(path: resolved, requirement: verifierRequirement)
        let directory = rooted(Self.verifierDirectory)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: attributes(mode: 0o755)
        )
        let destination = rooted(Self.verifierPath)
        try verifyTrustedAncestors(of: destination.deletingLastPathComponent())
        let privateStaging = directory.appending(component: "cc-sudo-exec.staging", directoryHint: .isDirectory)
        if fileManager.fileExists(atPath: privateStaging.path()) {
            try fileManager.removeItem(at: privateStaging)
        }
        try fileManager.createDirectory(
            at: privateStaging,
            withIntermediateDirectories: false,
            attributes: attributes(mode: 0o700)
        )
        defer { try? fileManager.removeItem(at: privateStaging) }
        let staging = privateStaging.appending(component: destination.lastPathComponent)
        try fileManager.copyItem(at: resolved, to: staging)
        var info = stat()
        guard lstat(staging.path(), &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw InstallError.verifierNotRegularFile(path: staging.path())
        }
        try hardenStagedTree([staging], fileManager: fileManager)
        try validator.validate(path: staging, requirement: verifierRequirement)
        try promote(staging, to: destination, fileManager: fileManager)
    }

    /// Stages the Caskroom authkit bundle into the root-owned
    /// `/Library/PrivilegedHelperTools/authkit.app` and freezes it so the
    /// runtime verifier and `prompt-helper` pin and spawn bytes the console user
    /// cannot rewrite after validation. The copy lands in a private 0700 staging
    /// dir no non-root code can enter, is proven symlink-free (the legit bundle
    /// has none; any link is hostile and fails closed), then hardened to
    /// root-owned, non-group/other-writable, ACL-free. Only the frozen bytes are
    /// validated against the authkit DR, the destination's ancestors are checked
    /// root-owned and unwritable, and the bundle is promoted by an atomic rename
    /// swap — no validate→promote→spawn race survives. The runtime verifier and
    /// `prompt-helper` re-resolve the inner executable themselves, so nothing is
    /// returned.
    func stageHelperBundle(from caskBundle: URL) throws {
        let fileManager = FileManager.default
        let directory = rooted(Self.verifierDirectory)
        try fileManager.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: attributes(mode: 0o755)
        )
        let destination = HelperTrust.stagedBundleURL(root: root)
        let privateStaging = directory.appending(component: "authkit.app.staging", directoryHint: .isDirectory)
        if fileManager.fileExists(atPath: privateStaging.path()) {
            try fileManager.removeItem(at: privateStaging)
        }
        try fileManager.createDirectory(
            at: privateStaging,
            withIntermediateDirectories: false,
            attributes: attributes(mode: 0o700)
        )
        defer { try? fileManager.removeItem(at: privateStaging) }
        let stagedBundle = privateStaging.appending(
            component: destination.lastPathComponent, directoryHint: .isDirectory
        )
        try fileManager.copyItem(at: caskBundle, to: stagedBundle)

        let entries = try provenSymlinkFreeEntries(under: stagedBundle, fileManager: fileManager)
        try hardenStagedTree(entries, fileManager: fileManager)
        try validator.validate(path: stagedBundle, requirement: helperRequirement)
        try verifyTrustedAncestors(of: destination.deletingLastPathComponent())
        try promote(stagedBundle, to: destination, fileManager: fileManager)
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

    /// Generates the console user's Secure-Enclave key through the just-installed
    /// root-owned verifier re-entered as `prompt-helper` — so the pinned cc-sudo
    /// binary, not a root `sudo` monitor, is authkit's parent and authkit's
    /// caller pin validates. `prompt-helper` re-resolves and re-pins the staged
    /// authkit itself.
    func enrollSelfKey(console: ConsoleUser) async throws -> String {
        let invocation = PrivilegedSpawn.launchctlInvocation(
            verifier: rooted(RunClient.verifierPath).path(),
            consoleUID: console.uid,
            authkitSubcommand: "keygen"
        )
        let result = try await runner.run(
            executable: invocation.executable,
            arguments: invocation.arguments,
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

extension Installer {
    /// Walks the copied tree WITHOUT following symlinks and returns every entry
    /// (the bundle root first) once proven symlink-free. Any symlink, or any
    /// enumeration/stat failure, fails closed before a single byte is hardened.
    private func provenSymlinkFreeEntries(under bundle: URL, fileManager: FileManager) throws -> [URL] {
        guard try !isSymbolicLink(bundle) else {
            throw InstallError.stagingContainsSymlink(path: bundle.path())
        }
        var enumerationFailed = false
        guard let enumerator = fileManager.enumerator(
            at: bundle,
            includingPropertiesForKeys: [.isSymbolicLinkKey],
            options: [],
            errorHandler: { _, _ in enumerationFailed = true; return false }
        ) else {
            throw InstallError.enumerationFailed(path: bundle.path())
        }
        var entries = [bundle]
        for case let url as URL in enumerator {
            guard try !isSymbolicLink(url) else {
                throw InstallError.stagingContainsSymlink(path: url.path())
            }
            entries.append(url)
        }
        guard !enumerationFailed else { throw InstallError.enumerationFailed(path: bundle.path()) }
        return entries
    }

    private func isSymbolicLink(_ url: URL) throws -> Bool {
        guard let isLink = try url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink else {
            throw InstallError.enumerationFailed(path: url.path())
        }
        return isLink
    }

    /// Freezes the proven-symlink-free tree: set-ID and group/other write
    /// stripped, ACLs cleared no-follow, ownership set to root (only as root).
    private func hardenStagedTree(_ entries: [URL], fileManager: FileManager) throws {
        let isRoot = geteuid() == 0
        for url in entries {
            var info = stat()
            guard lstat(url.path(), &info) == 0 else {
                throw InstallError.hardeningFailed(path: url.path())
            }
            var attributes: [FileAttributeKey: Any] = [
                .posixPermissions: Int16((info.st_mode & 0o7777) & ~UInt16(0o6022)),
            ]
            if isRoot {
                attributes[.ownerAccountID] = 0
                attributes[.groupOwnerAccountID] = 0
            }
            try fileManager.setAttributes(attributes, ofItemAtPath: url.path())
            try clearExtendedACL(at: url)
        }
    }

    private func clearExtendedACL(at url: URL) throws {
        guard let empty = acl_init(0) else { throw InstallError.hardeningFailed(path: url.path()) }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        guard url.path().withCString({ acl_set_link_np($0, ACL_TYPE_EXTENDED, empty) }) == 0 else {
            throw InstallError.hardeningFailed(path: url.path())
        }
    }

    /// Whether the path carries any extended ACL, read no-follow. The trusted
    /// ancestor chain is ACL-free, so any extended ACL on an ancestor is treated
    /// as untrusted and fails closed rather than being parsed for a grant.
    private func hasExtendedACL(at path: String) -> Bool {
        guard let acl = path.withCString({ acl_get_link_np($0, ACL_TYPE_EXTENDED) }) else {
            return false
        }
        acl_free(UnsafeMutableRawPointer(acl))
        return true
    }

    /// Requires each ancestor up to the rooted filesystem root to be a real
    /// directory (no-follow), not group/other writable, ACL-free, root-owned.
    private func verifyTrustedAncestors(of leaf: URL) throws {
        let isRoot = geteuid() == 0
        let stop = canonicalPath(root)
        var current = leaf
        while true {
            let path = noFollowPath(current)
            var info = stat()
            guard lstat(path, &info) == 0 else {
                throw InstallError.untrustedAncestor(path: path)
            }
            guard (info.st_mode & S_IFMT) == S_IFDIR else {
                throw InstallError.untrustedAncestor(path: path)
            }
            guard (info.st_mode & 0o022) == 0 else {
                throw InstallError.untrustedAncestor(path: path)
            }
            guard !hasExtendedACL(at: path) else {
                throw InstallError.untrustedAncestor(path: path)
            }
            if isRoot, info.st_uid != 0 {
                throw InstallError.untrustedAncestor(path: path)
            }
            if canonicalPath(current) == stop {
                break
            }
            let parent = current.deletingLastPathComponent()
            if canonicalPath(parent) == canonicalPath(current) {
                break
            }
            current = parent
        }
    }

    /// The literal path for the no-follow probes: `deletingLastPathComponent()`
    /// leaves a trailing slash, which makes `lstat` and `acl_get_link_np`
    /// follow a final-component directory symlink.
    private func noFollowPath(_ url: URL) -> String {
        var path = url.path(percentEncoded: false)
        if path.count > 1, path.hasSuffix("/") {
            path.removeLast()
        }
        return path
    }

    private func canonicalPath(_ url: URL) -> String {
        var path = url.standardizedFileURL.path(percentEncoded: false)
        if path.count > 1, path.hasSuffix("/") {
            path.removeLast()
        }
        return path
    }

    /// Atomically swaps the hardened staged bundle into place — a RENAME_SWAP
    /// when the destination exists (the old tree is then removed), a plain
    /// rename otherwise — so the destination is never a half-populated tree.
    private func promote(_ stagedBundle: URL, to destination: URL, fileManager: FileManager) throws {
        if fileManager.fileExists(atPath: destination.path()) {
            let swapped = stagedBundle.path().withCString { source in
                destination.path().withCString { target in
                    renamex_np(source, target, UInt32(RENAME_SWAP))
                }
            }
            guard swapped == 0 else { throw InstallError.hardeningFailed(path: destination.path()) }
            try fileManager.removeItem(at: stagedBundle)
        } else {
            let renamed = stagedBundle.path().withCString { source in
                destination.path().withCString { target in
                    rename(source, target)
                }
            }
            guard renamed == 0 else { throw InstallError.hardeningFailed(path: destination.path()) }
        }
    }
}
