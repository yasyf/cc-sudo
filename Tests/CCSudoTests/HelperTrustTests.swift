@testable import CCSudo
import Foundation
import Testing

@Test func requirementPinsTeamIdentifierAndDeveloperIDAnchors() {
    let requirement = HelperTrust.requirementString()
    #expect(requirement == "identifier \"com.yasyf.authkit\""
        + " and anchor apple generic"
        + " and certificate 1[field.1.2.840.113635.100.6.2.6]"
        + " and certificate leaf[field.1.2.840.113635.100.6.1.13]"
        + " and certificate leaf[subject.OU] = \"SXKCTF23Q2\"")
}

@Test func missingCaskFailsClosedWithTheSearchedPaths() {
    do {
        _ = try HelperTrust.locateBundle(fileManager: FileManager())
        // The cask may genuinely be installed on a dev machine; nothing to
        // assert in that case.
    } catch let HelperTrust.HelperError.notInstalled(searched) {
        #expect(searched.contains("/opt/homebrew/Caskroom/authkit"))
        #expect(searched.contains("/usr/local/Caskroom/authkit"))
    } catch {
        Issue.record("unexpected error \(error)")
    }
}

@Test func anUnsignedBundleFailsTheDesignatedRequirementPin() throws {
    // A structurally valid but unsigned "bundle": the pin must reject it long
    // before any signature is trusted (fail closed, never fail open).
    let bundle = FileManager.default.temporaryDirectory
        .appending(component: "fake-\(UUID().uuidString)", directoryHint: .isDirectory)
        .appending(component: "authkit.app", directoryHint: .isDirectory)
    let macos = bundle.appending(path: "Contents/MacOS")
    try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: macos.appending(component: "authkit"))

    #expect(throws: HelperTrust.HelperError.self) {
        try HelperTrust.validate(bundle: bundle)
    }
}

/// The real pin against the installed cask — only meaningful where the signed
/// authkit is present (skips in CI and on machines without the cask).
@Test(.enabled(if: (try? HelperTrust.locateBundle()) != nil))
func installedAuthkitBundleSatisfiesThePin() throws {
    let binary = try HelperTrust.pinnedHelperBinary()
    #expect(binary.path().hasSuffix("authkit.app/Contents/MacOS/authkit"))
}

@Test func aWrongTeamRequirementRejectsEvenAValidBundle() throws {
    guard let bundle = try? HelperTrust.locateBundle() else {
        return // no cask on this machine; the negative is covered by the unsigned-bundle test
    }
    #expect(throws: HelperTrust.HelperError.self) {
        try HelperTrust.validate(
            bundle: bundle,
            requirement: HelperTrust.requirementString(teamID: "WRONG00000")
        )
    }
}

/// M1: the runtime trust anchor is the ROOT-OWNED staged path, never a
/// user-writable Caskroom path, and it is always validated before use.
@Test func theRuntimeHelperAnchorIsTheRootOwnedStagedPath() throws {
    #expect(HelperTrust.stagedBundlePath == "/Library/PrivilegedHelperTools/authkit.app")
    #expect(!HelperTrust.stagedBundlePath.contains("Caskroom"))
    #expect(!HelperTrust.stagedBundlePath.contains("Cellar"))

    // A missing staged bundle fails closed with a "run install" signal.
    let emptyRoot = FileManager.default.temporaryDirectory
        .appending(component: "anchor-\(UUID().uuidString)", directoryHint: .isDirectory)
    try FileManager.default.createDirectory(at: emptyRoot, withIntermediateDirectories: true)
    #expect(throws: HelperTrust.HelperError.self) {
        _ = try HelperTrust.stagedHelperBinary(root: emptyRoot)
    }

    // A present-but-unsigned staged bundle is validated (not trusted blindly).
    let bundle = emptyRoot.appending(path: "Library/PrivilegedHelperTools/authkit.app")
    let macos = bundle.appending(path: "Contents/MacOS")
    try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
    let binary = macos.appending(component: "authkit")
    try Data("#!/bin/sh\nexit 0\n".utf8).write(to: binary)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: binary.path())
    #expect(throws: HelperTrust.HelperError.self) {
        _ = try HelperTrust.stagedHelperBinary(root: emptyRoot)
    }
}
