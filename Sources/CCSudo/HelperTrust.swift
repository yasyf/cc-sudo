import Foundation
import os
import Security

/// The LOAD-BEARING reverse pin: the root verifier locates the authkit bundle
/// at its known Caskroom staging path and validates it with
/// `SecStaticCodeCreateWithPath` + `SecStaticCodeCheckValidity` against the
/// pinned designated requirement BEFORE trusting any signature it returns.
/// Root spawns exactly the binary it validated, so this anchor is unspoofable
/// by user-level code — authkit's own invoker-pin is defense-in-depth on top
/// (its audit token is self-reported under the exec/stdin transport), and the
/// escalation boundary is this pin + the SE key's user-presence ACL + the
/// root-generated nonce.
///
/// The requirement pins the Team ID + code-signing identifier — the DR, never
/// a bare cdhash — so a legitimately re-signed authkit release keeps
/// validating. The verifier NEVER honors AUTHKIT_HELPER here: an
/// attacker-controllable environment variable must not steer the trust anchor.
public enum HelperTrust {
    public enum HelperError: Error, Sendable {
        case notInstalled(searched: [String])
        case bundleUnreadable(path: String, status: OSStatus)
        case requirementInvalid(OSStatus)
        case pinRejected(path: String, status: OSStatus)
    }

    /// authkit ships from the same Apple Developer Team as cc-sudo.
    public static let pinnedTeamID = "SXKCTF23Q2"

    /// The authkit.app code-signing identifier (its CFBundleIdentifier).
    public static let pinnedIdentifier = "com.yasyf.authkit"

    static let caskName = "authkit"
    static let appName = "authkit.app"
    static let executableSubpath = "Contents/MacOS/authkit"
    static let caskroomPrefixes = ["/opt/homebrew", "/usr/local"]

    /// The pinned designated requirement: the authkit identifier, signed
    /// Developer ID (leaf and intermediate marker OIDs), under the pinned team.
    /// Mirrors AuthKit.CallerCheck.requirementString — the two pins must agree
    /// on shape or a release that satisfies one fails the other.
    public static func requirementString(
        teamID: String = pinnedTeamID,
        identifier: String = pinnedIdentifier
    ) -> String {
        "identifier \"\(identifier)\""
            + " and anchor apple generic"
            + " and certificate 1[field.1.2.840.113635.100.6.2.6]"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13]"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }

    /// Locates the staged authkit.app across the known Caskroom prefixes. The
    /// cask stages the bundle (stage_only) so the bundle-relative provisioning
    /// profile that authorizes the Secure Enclave stays intact.
    public static func locateBundle(fileManager: FileManager = .default) throws -> URL {
        var searched: [String] = []
        for prefix in caskroomPrefixes {
            let caskDirectory = URL(filePath: prefix, directoryHint: .isDirectory)
                .appending(components: "Caskroom", caskName)
            searched.append(caskDirectory.path())
            guard let versions = try? fileManager.contentsOfDirectory(
                at: caskDirectory, includingPropertiesForKeys: nil
            ) else { continue }
            for version in versions.sorted(by: { $0.path() > $1.path() }) {
                let bundle = version.appending(component: appName)
                let binary = bundle.appending(path: executableSubpath)
                if fileManager.isExecutableFile(atPath: binary.path()) {
                    return bundle
                }
            }
        }
        throw HelperError.notInstalled(searched: searched)
    }

    /// Validates the bundle at `bundle` against the pinned designated
    /// requirement. Throws on ANY failure — there is no unsigned fallback.
    public static func validate(bundle: URL, requirement: String = requirementString()) throws {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(bundle as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let staticCode else {
            throw HelperError.bundleUnreadable(path: bundle.path(), status: createStatus)
        }

        var secRequirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(requirement as CFString, [], &secRequirement)
        guard requirementStatus == errSecSuccess, let secRequirement else {
            throw HelperError.requirementInvalid(requirementStatus)
        }

        let validity = SecStaticCodeCheckValidity(staticCode, [], secRequirement)
        guard validity == errSecSuccess else {
            Logger.verifier.error(
                "authkit pin rejected at \(bundle.path(), privacy: .public): OSStatus \(validity, privacy: .public)"
            )
            throw HelperError.pinRejected(path: bundle.path(), status: validity)
        }
    }

    /// Locate + validate in one step; returns the inner executable the verifier
    /// spawns. The returned path IS the validated path — callers must exec it
    /// verbatim, never re-resolve.
    public static func pinnedHelperBinary() throws -> URL {
        let bundle = try locateBundle()
        try validate(bundle: bundle)
        return bundle.appending(path: executableSubpath)
    }
}
