import AuthKit
@testable import CCSudo
import Foundation
import Testing

@Test func sudoersRuleIsExactlyTheFrozenLine() {
    #expect(Installer.sudoersRule == "%admin ALL=(root) NOPASSWD: /Library/PrivilegedHelperTools/cc-sudo-exec\n")
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
    return root
}

/// A fake authkit.app the installer can copy — a real directory with the inner
/// executable so `copyItem` and the staged-path resolution have something to
/// walk. Provenance is checked by the injected `StubCodeSignatureValidator`.
private func fakeHelperBundle(in root: URL) throws -> URL {
    let bundle = root.appending(component: "authkit.app", directoryHint: .isDirectory)
    let macos = bundle.appending(path: "Contents/MacOS")
    try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
    let binary = macos.appending(component: "authkit")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: binary)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path())
    return bundle
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
        case LocalHelper.launchctl: SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
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

    // The keygen ran through launchctl asuser + sudo -u as the console user,
    // against the STAGED root-owned helper — never the Caskroom path.
    let keygenSpawn = try #require(runner.spawns.first(where: { $0.executable == LocalHelper.launchctl }))
    #expect(keygenSpawn.arguments == [
        "asuser", "501",
        "/usr/bin/sudo", "-u", "#501", "-H",
        stagedHelper.path(), "keygen",
    ])
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
        executable == LocalHelper.launchctl
            ? SubprocessResult(exitCode: 0, stdout: keygenOutput, stderr: Data())
            : .exit(0)
    }
    // The SOURCE binary passes the cc-sudo self-pin; the STAGED
    // cc-sudo-exec.installing copy fails it — a source swapped mid-copy. Only
    // the staged-copy check (validate AFTER the copy, BEFORE replaceItemAt)
    // can catch this, so this test fails if that validation is removed.
    let validator = StubCodeSignatureValidator { path, requirement in
        requirement == DesignatedRequirement.string(identifier: DesignatedRequirement.ccSudoIdentifier)
            && path.lastPathComponent == "cc-sudo-exec.installing"
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
    #expect(runner.spawns.allSatisfy { $0.executable != LocalHelper.launchctl })
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
        executable == LocalHelper.launchctl ? .exit(2, stderr: "no provisioned bundle") : .exit(0)
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
        executable == LocalHelper.launchctl
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
