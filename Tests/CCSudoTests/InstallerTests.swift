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
    let installer = Installer(runner: runner, root: root, euid: { 0 })

    let source = root.appending(component: "cc-sudo-binary")
    try Data("#!/bin/sh\n".utf8).write(to: source)

    let keyID = try await installer.install(
        sourceExecutable: source,
        originIdentity: "laptop",
        pinnedHelper: URL(filePath: "/pinned/authkit.app/Contents/MacOS/authkit"),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )
    #expect(keyID == "kid123")

    let verifier = root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec")
    #expect(FileManager.default.fileExists(atPath: verifier.path()))

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

    // The keygen ran through launchctl asuser + sudo -u as the console user.
    let keygenSpawn = try #require(runner.spawns.first(where: { $0.executable == LocalHelper.launchctl }))
    #expect(keygenSpawn.arguments == [
        "asuser", "501",
        "/usr/bin/sudo", "-u", "#501", "-H",
        "/pinned/authkit.app/Contents/MacOS/authkit", "keygen",
    ])
}

@Test func installRefusesWithoutRoot() async throws {
    let root = try temporaryRoot()
    let installer = Installer(runner: FakeRunner { _, _ in .exit(0) }, root: root, euid: { 501 })
    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: root.appending(component: "x"),
            originIdentity: "laptop",
            pinnedHelper: URL(filePath: "/pinned/authkit"),
            console: ConsoleUser(name: "yasyf", uid: 501)
        )
    }
}

@Test func rejectedSudoersAbortsBeforeInstallingTheRule() async throws {
    let root = try temporaryRoot()
    let runner = FakeRunner { executable, _ in
        executable == Installer.visudo ? .exit(1, stderr: "syntax error") : .exit(0)
    }
    let installer = Installer(runner: runner, root: root, euid: { 0 })
    let source = root.appending(component: "cc-sudo-binary")
    try Data("#!/bin/sh\n".utf8).write(to: source)

    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: source,
            originIdentity: "laptop",
            pinnedHelper: URL(filePath: "/pinned/authkit"),
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
    let installer = Installer(runner: runner, root: root, euid: { 0 })
    let source = root.appending(component: "cc-sudo-binary")
    try Data("#!/bin/sh\n".utf8).write(to: source)

    await #expect(throws: Installer.InstallError.self) {
        _ = try await installer.install(
            sourceExecutable: source,
            originIdentity: "laptop",
            pinnedHelper: URL(filePath: "/pinned/authkit"),
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
    let installer = Installer(runner: runner, root: root, euid: { 0 })
    let source = root.appending(component: "cc-sudo-binary")
    try Data("#!/bin/sh\n".utf8).write(to: source)
    _ = try await installer.install(
        sourceExecutable: source,
        originIdentity: "laptop",
        pinnedHelper: URL(filePath: "/pinned/authkit"),
        console: ConsoleUser(name: "yasyf", uid: 501)
    )

    try installer.uninstall()
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/sudoers.d/cc-sudo").path()))
    let verifier = root.appending(path: "Library/PrivilegedHelperTools/cc-sudo-exec")
    #expect(!FileManager.default.fileExists(atPath: verifier.path()))
    #expect(!FileManager.default.fileExists(atPath: root.appending(path: "etc/cc-sudo").path()))
}
