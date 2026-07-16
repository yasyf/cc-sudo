import Foundation
import os
import Security

/// Builds the Developer-ID designated requirement that pins a code-signing
/// identifier under cc-sudo's Apple Developer Team. It pins the DR (Team ID +
/// identifier), never a bare cdhash, so a legitimately re-signed release keeps
/// validating. The authkit reverse-pin (`HelperTrust`) and this cc-sudo
/// self-pin share the same shape — they must agree or a release that satisfies
/// one fails the other.
public enum DesignatedRequirement {
    /// cc-sudo and authkit ship from the same Apple Developer Team.
    public static let pinnedTeamID = "SXKCTF23Q2"

    /// cc-sudo's own code-signing identifier. The root-owned verifier is a copy
    /// of the cc-sudo binary, so it carries this identifier — the install-time
    /// provenance check validates a candidate binary against it.
    public static let ccSudoIdentifier = "cc-sudo"

    /// The pinned requirement: the identifier, signed Developer ID (leaf and
    /// intermediate marker OIDs), under the pinned team.
    public static func string(identifier: String, teamID: String = pinnedTeamID) -> String {
        "identifier \"\(identifier)\""
            + " and anchor apple generic"
            + " and certificate 1[field.1.2.840.113635.100.6.2.6]"
            + " and certificate leaf[field.1.2.840.113635.100.6.1.13]"
            + " and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}

/// Validates a signed binary or bundle at a path against a designated
/// requirement. Split behind a protocol so the installer's provenance check is
/// testable headless (like the runner/euid seams) while production wires the
/// real `SecStaticCode` DR check.
public protocol CodeSignatureValidator: Sendable {
    func validate(path: URL, requirement: String) throws
}

public enum CodeSignatureError: Error, Sendable {
    case unreadable(path: String, status: OSStatus)
    case requirementInvalid(OSStatus)
    case rejected(path: String, status: OSStatus)
}

/// The production validator: `SecStaticCodeCreateWithPath` +
/// `SecStaticCodeCheckValidity` against the pinned DR. Fail-closed on any
/// failure — there is no unsigned fallback.
public struct LiveCodeSignatureValidator: CodeSignatureValidator {
    public init() {}

    public func validate(path: URL, requirement: String) throws {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(path as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let staticCode else {
            throw CodeSignatureError.unreadable(path: path.path(), status: createStatus)
        }

        var secRequirement: SecRequirement?
        let requirementStatus = SecRequirementCreateWithString(requirement as CFString, [], &secRequirement)
        guard requirementStatus == errSecSuccess, let secRequirement else {
            throw CodeSignatureError.requirementInvalid(requirementStatus)
        }

        let validity = SecStaticCodeCheckValidity(staticCode, [], secRequirement)
        guard validity == errSecSuccess else {
            Logger.installer.error(
                "code signature rejected at \(path.path(), privacy: .public): OSStatus \(validity, privacy: .public)"
            )
            throw CodeSignatureError.rejected(path: path.path(), status: validity)
        }
    }
}
