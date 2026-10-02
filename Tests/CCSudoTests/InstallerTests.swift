import AuthKit
@testable import CCSudo
import Foundation
import Testing

@Test func sudoersRuleGrantsOnlyTheExecEntrypoint() {
    // NOPASSWD is scoped to `exec` — never the bare binary — so admin-session
    // code cannot reach the privileged `prompt-helper` shim or the setup
    // subcommands through the rule.
    #expect(Installer.sudoersRule == "%admin ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/cc-sudo-exec exec *\n")
    #expect(Installer.sudoersRule.contains(" exec *"))
    #expect(!Installer.sudoersRule.contains("prompt-helper"))
}

@Test func verifierPathIsNeverAHomebrewPath() {
    #expect(!Installer.verifierPath.contains("Cellar"))
    #expect(!Installer.verifierPath.contains("Caskroom"))
    #expect(!Installer.verifierPath.contains("homebrew"))
    #expect(Installer.verifierPath.hasPrefix("/Library/PrivilegedHelperTools/"))
}

private func temporaryRoot() throws -> URL {
    let root = FileManager.default.temporaryDirectory
        .appending(component: "install-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    // The staging ancestor-trust check walks up to `root`, so pin it
    // non-group/other-writable regardless of the test host's umask.
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path())
    return root
}

/// A fake authkit.app the installer can copy — a real directory with the inner
/// executable so `copyItem` and the staged-path resolution have something to
/// walk. `innerMode` seeds the staged file's permissions so a test can observe
/// the installer strip group/other write. Provenance is checked by the injected
/// `StubCodeSignatureValidator`.
private func fakeHelperBundle(in root: URL, innerMode: Int = 0o755) throws -> URL {
    let bundle = root.appending(component: "authkit.app", directoryHint: .isDirectory)
    let macos = bundle.appending(path: "Contents/MacOS")
    try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
    let binary = macos.appending(component: "authkit")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: binary)
    try FileManager.default.setAttributes([.posixPermissions: innerMode], ofItemAtPath: binary.path())
    return bundle
}

/// A fake authkit.app carrying symlinks — the legit bundle has none, so the
/// installer must reject any it finds. One link escapes via an absolute path,
/// one via a relative `..` path.
private func fakeHelperBundleWithSymlink(in root: URL) throws -> URL {
    let bundle = try fakeHelperBundle(in: root)
    let fileManager = FileManager.default
    try fileManager.createSymbolicLink(
        atPath: bundle.appending(path: "Contents/evil").path(),
        withDestinationPath: "/etc/passwd"
    )
    try fileManager.createSymbolicLink(
        atPath: bundle.appending(path: "Contents/escape").path(),
        withDestinationPath: "../../../../etc/passwd"
    )
    return bundle
}

private func posixMode(at url: URL) throws -> UInt16 {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path())
    return try #require((attributes[.posixPermissions] as? NSNumber)?.uint16Value)
}

/// A source "cc-sudo" binary the installer copies to the verifier path.
private func fakeSourceBinary(in root: URL) throws -> URL {
    let source = root.appending(component: "cc-sudo-binary")
    try Data("#!/bin/sh\n".utf8).write(to: source)
    return source
}

@Test func installLaysDownVerifierSudoersKeyAndOrigin() async throws {
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(
        KeygenResponse(keyID: "kid123", publicKey: signer.publicKeyBase64)
    )

    let runner = FakeRunner { executable, _ in
        switch executable {
        case Installer.visudo: .exit(0)
        case PrivilegedSpawn.launchctl: SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
        default: .exit(1, stderr: "unexpected spawn \(executable)")
        }
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())

    let source = try fakeSourceBinary(in: root)
    let bundle = try fakeHelperBundle(in: root)

    let keyID = try await installer.install(
        sourceExecutable: source,
        originIdentity: "laptop",
        helperBundle: bundle,
        console: ConsoleUser(name: "yasyf", uid: 501)
    )
    #expect(keyID == "kid123")

    let verifier = root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec")
    #expect(FileManager.default.fileExists(atPath: verifier.path()))

    // The authkit bundle was staged root-owned, not left at the Caskroom path.
    let stagedHelper = root.appending(path: "Library/PrivilegedHelperTools/authkit.app/Contents/MacOS/authkit")
    #expect(FileManager.default.isExecutableFile(atPath: stagedHelper.path()))

    let sudoers = try String(
        contentsOf: root.appending(path: "etc/sudoers.d/cc-sudo"), encoding: .utf8
    )
    #expect(sudoers == Installer.sudoersRule)

    let enrolled = try String(
        contentsOf: root.appending(path: "etc/cc-sudo/trusted/self.pub"), encoding: .utf8
    )
    #expect(enrolled.trimmingCharacters(in: .whitespacesAndNewlines) == signer.publicKeyBase64)

    let origin = try String(contentsOf: root.appending(path: "etc/cc-sudo/origin-host"), encoding: .utf8)
    #expect(origin == "laptop\n")

    // The keygen ran through `launchctl asuser` re-entering the just-installed
    // root verifier as prompt-helper — so the pinned cc-sudo binary, not a root
    // `sudo` monitor, is authkit's parent. authkit is resolved inside
    // prompt-helper, never named on the command line, and `sudo -u` is gone.
    let keygenSpawn = try #require(runner.spawns.first(where: { $0.executable == PrivilegedSpawn.launchctl }))
    #expect(keygenSpawn.arguments == [
        "asuser", "501",
        verifier.path(), "prompt-helper", "--uid", "501",
        "--", "keygen",
    ])
    #expect(!keygenSpawn.arguments.contains("/usr/bin/sudo"))
}

@Test func installRejectsAnUnsignedVerifierSourceBeforeAnyCopy() async throws {
    let root = try temporaryRoot()
    let runner = FakeRunner { _, _ in .exit(0) }
    // Reject exactly the cc-sudo self-pin — the source binary fails provenance.
    let validator = StubCodeSignatureValidator { _, requirement in
        requirement == DesignatedRequirement.string(identifier: DesignatedRequirement.ccSudoIdentifier)
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: validator)

    await #expect(throws: CodeSignatureError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundle(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    // Nothing was promoted to the NOPASSWD verifier path.
    #expect(!FileManager.default.fileExists(
        atPath: root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec").path()
    ))
}

@Test func installRejectsATamperedStagedVerifierBeforePromotion() async throws {
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(
        KeygenResponse(keyID: "kid123", publicKey: signer.publicKeyBase64)
    )
    // A fully-succeeding runner: were the staged-copy validation deleted,
    // install would run to completion and promote the tampered binary.
    let runner = FakeRunner { executable, _ in
        executable == PrivilegedSpawn.launchctl
            ? SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
            : .exit(0)
    }
    // The SOURCE binary passes the cc-sudo self-pin; the copy staged under
    // cc-sudo-exec.staging fails it — a source swapped mid-copy. Only the
    // staged-copy check (validate AFTER the copy, BEFORE promotion) can catch
    // this, so this test fails if that validation is removed.
    let validator = StubCodeSignatureValidator { path, requirement in
        requirement == DesignatedRequirement.string(identifier: DesignatedRequirement.ccSudoIdentifier)
            && path.path().contains("cc-sudo-exec.staging")
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: validator)

    await #expect(throws: CodeSignatureError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundle(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    // The tampered staged copy was never promoted to the NOPASSWD verifier path.
    #expect(!FileManager.default.fileExists(
        atPath: root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec").path()
    ))
    // Install aborted inside installVerifier: no sudoers check, no keygen ran.
    #expect(runner.spawns.isEmpty)
}

@Test func installRejectsAWrongTeamStagedHelperBeforePromotion() async throws {
    let root = try temporaryRoot()
    let runner = FakeRunner { executable, _ in
        executable == Installer.visudo ? .exit(0) : .exit(0)
    }
    // Accept the cc-sudo verifier copy but reject the authkit staged copy: the
    // staged bytes (the ones that would be promoted and later spawned as root)
    // fail the reverse-pin, so nothing lands at the root-owned helper path.
    let validator = StubCodeSignatureValidator { _, requirement in
        requirement == HelperTrust.requirementString()
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: validator)

    await #expect(throws: CodeSignatureError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundle(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    #expect(!FileManager.default.fileExists(
        atPath: root.appending(path: "Library/PrivilegedHelperTools/authkit.app").path()
    ))
    // The staged helper never validated, so keygen never ran.
    #expect(runner.spawns.allSatisfy { $0.executable != PrivilegedSpawn.launchctl })
}

@Test func installRejectsASymlinkInTheStagedBundle() async throws {
    let root = try temporaryRoot()
    // A fully-succeeding runner and validator: the install must still fail
    // closed on the symlink alone, before validation or promotion.
    let runner = FakeRunner { _, _ in .exit(0) }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())

    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundleWithSymlink(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    // Nothing poisoned was promoted to the root-owned helper path.
    #expect(!FileManager.default.fileExists(
        atPath: root.appending(path: "Library/PrivilegedHelperTools/authkit.app").path()
    ))
    // Rejection precedes the keygen spawn.
    #expect(runner.spawns.allSatisfy { $0.executable != PrivilegedSpawn.launchctl })
}

@Test func installStripsSetIDAndGroupOtherWriteFromTheStagedBundle() async throws {
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(
        KeygenResponse(keyID: "kid123", publicKey: signer.publicKeyBase64)
    )
    let runner = FakeRunner { executable, _ in
        switch executable {
        case Installer.visudo: .exit(0)
        case PrivilegedSpawn.launchctl: SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
        default: .exit(1, stderr: "unexpected spawn \(executable)")
        }
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())

    _ = try await installer.install(
        sourceExecutable: fakeSourceBinary(in: root),
        originIdentity: "laptop",
        helperBundle: fakeHelperBundle(in: root, innerMode: 0o6777),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )

    // A setuid/setgid, world-writable source file lands as a plain 0o755 — set-ID
    // and group/other write stripped, read/exec preserved.
    let stagedHelper = root.appending(path: "Library/PrivilegedHelperTools/authkit.app/Contents/MacOS/authkit")
    let mode = try posixMode(at: stagedHelper)
    #expect(mode == 0o755)
}

@Test func installAtomicallyReplacesAnExistingStagedBundle() async throws {
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(
        KeygenResponse(keyID: "kid123", publicKey: signer.publicKeyBase64)
    )
    let runner = FakeRunner { executable, _ in
        switch executable {
        case Installer.visudo: .exit(0)
        case PrivilegedSpawn.launchctl: SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
        default: .exit(1, stderr: "unexpected spawn \(executable)")
        }
    }

    // A stale root-owned bundle already sits at the destination, carrying a
    // marker the fresh install must not inherit.
    let helperTools = root.appending(path: "Library/PrivilegedHelperTools")
    let existing = helperTools.appending(path: "authkit.app")
    try FileManager.default.createDirectory(
        at: existing.appending(path: "Contents/MacOS"), withIntermediateDirectories: true
    )
    let library = root.appending(path: "Library")
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helperTools.path())
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: library.path())
    try Data("stale".utf8).write(to: existing.appending(path: "Contents/MacOS/authkit"))
    try Data("marker".utf8).write(to: existing.appending(component: "MARKER"))

    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())
    _ = try await installer.install(
        sourceExecutable: fakeSourceBinary(in: root),
        originIdentity: "laptop",
        helperBundle: fakeHelperBundle(in: root, innerMode: 0o777),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )

    // The stale marker is gone and the new hardened binary is in place.
    #expect(!FileManager.default.fileExists(atPath: existing.appending(component: "MARKER").path()))
    let stagedHelper = existing.appending(path: "Contents/MacOS/authkit")
    #expect(FileManager.default.isExecutableFile(atPath: stagedHelper.path()))
    let mode = try posixMode(at: stagedHelper)
    #expect(mode & 0o022 == 0)

    // No staging or temp directory leaked into the root-owned helper dir.
    let leftovers = try FileManager.default.contentsOfDirectory(atPath: helperTools.path())
    #expect(leftovers.allSatisfy { !$0.hasSuffix(".staging") && !$0.hasSuffix(".installing") })
    #expect(leftovers.contains("authkit.app"))
}

@Test func installRefusesWithoutRoot() async throws {
    let root = try temporaryRoot()
    let installer = Installer(
        runner: FakeRunner { _, _ in .exit(0) }, root: root, euid: { 501 },
        validator: StubCodeSignatureValidator()
    )
    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: root.appending(component: "x"),
            originIdentity: "laptop",
            helperBundle: root.appending(component: "authkit.app"),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
}

@Test func rejectedSudoersAbortsBeforeInstallingTheRule() async throws {
    let root = try temporaryRoot()
    let runner = FakeRunner { executable, _ in
        executable == Installer.visudo ? .exit(1, stderr: "syntax error") : .exit(0)
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())

    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundle(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/sudoers.d/cc-sudo").path()))
}

@Test func failedKeygenAbortsEnrollment() async throws {
    let root = try temporaryRoot()
    let runner = FakeRunner { executable, _ in
        executable == PrivilegedSpawn.launchctl ? .exit(2, stderr: "no provisioned bundle") : .exit(0)
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())

    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: fakeSourceBinary(in: root),
            originIdentity: "laptop",
            helperBundle: fakeHelperBundle(in: root),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/cc-sudo/trusted/self.pub").path()))
}

@Test func uninstallRemovesEverythingItInstalled() async throws {
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(KeygenResponse(keyID: "k", publicKey: signer.publicKeyBase64))
    let runner = FakeRunner { executable, _ in
        executable == PrivilegedSpawn.launchctl
            ? SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
            : .exit(0)
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())
    _ = try await installer.install(
        sourceExecutable: fakeSourceBinary(in: root),
        originIdentity: "laptop",
        helperBundle: fakeHelperBundle(in: root),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )

    try installer.uninstall()
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/sudoers.d/cc-sudo").path()))
    let verifier = root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec")
    #expect(!FileManager.default.fileExists(atPath: verifier.path()))
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/cc-sudo").path()))
}

@Test func installReplacesASymlinkVerifierWithARegularRootOwnedCopy() async throws {
    let fileManager = FileManager.default
    let root = try temporaryRoot()
    let signer = TestSigner()
    let keygenOutput = try JSONEncoder().encode(KeygenResponse(keyID: "k", publicKey: signer.publicKeyBase64))
    let runner = FakeRunner { executable, _ in
        executable == PrivilegedSpawn.launchctl
            ? SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
            : .exit(0)
    }
    // Seed the Caskroom-symlink state the fix must replace: the destination
    // verifier is a symlink into a user-writable file.
    let phtDir = root.appending(path: "Library/PrivilegedHelperTools", directoryHint: .isDirectory)
    try fileManager.createDirectory(at: phtDir, withIntermediateDirectories: true)
    let userBytes = root.appending(component: "user-cc-sudo")
    try Data("#!/bin/sh\n".utf8).write(to: userBytes)
    let verifier = phtDir.appending(component: "cc-sudo-exec")
    try fileManager.createSymbolicLink(at: verifier, withDestinationURL: userBytes)

    let installer = Installer(runner: runner, root: root, euid: { 0 }, validator: StubCodeSignatureValidator())
    _ = try await installer.install(
        sourceExecutable: fakeSourceBinary(in: root),
        originIdentity: "laptop",
        helperBundle: fakeHelperBundle(in: root),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )

    // The promoted verifier is a regular file, not the user-writable symlink.
    #expect((try? fileManager.destinationOfSymbolicLink(atPath: verifier.path())) == nil)
    let attributes = try fileManager.attributesOfItem(atPath: verifier.path())
    let mode = try #require((attributes[.posixPermissions] as? NSNumber)?.intValue)
    #expect(mode & 0o022 == 0)
}
