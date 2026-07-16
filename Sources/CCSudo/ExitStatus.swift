import AuthKit

/// The documented cc-sudo exit codes an agent can route on. An approved
/// command's own exit status passes through verbatim, so these sit high and
/// distinct; anything else non-zero is an unclassified failure (usage errors,
/// I/O). The MCP `run_command` verdict field derives from the same table.
///
///   103 denied — the human rejected the sheet; terminal, never retried
///   104 unavailable — no prompt path could fire (no console user, screen
///       locked with no live peer, synckitd unreachable)
///   105 verificationFailed — signature rejected, enrolled key missing or
///       malformed, or the authkit bundle failed its designated-requirement pin
///   106 versionSkew — CLI and root-owned verifier disagree; run `cc-sudo install`
public enum ExitStatus: Int32, Sendable {
    case denied = 103
    case unavailable = 104
    case verificationFailed = 105
    case versionSkew = 106

    /// Classifies a thrown error onto the documented exit table; nil means the
    /// error is not one of the routable outcomes.
    public init?(classifying error: any Error) {
        switch error {
        case ConsentError.denied:
            self = .denied
        case ConsentError.unavailable, ConsentError.screenLocked:
            self = .unavailable
        case is VerifierError, is TrustStore.TrustError, is HelperTrust.HelperError,
             is Attestation.VerificationError, is OriginIdentity.OriginError:
            self = .verificationFailed
        case is VersionSkewError:
            self = .versionSkew
        default:
            return nil
        }
    }

    /// The verdict string the MCP tool reports for a verifier exit code; an
    /// unlisted code means the approved command itself exited with it.
    public static func verdict(forExitCode code: Int32) -> String {
        switch ExitStatus(rawValue: code) {
        case .denied: "denied"
        case .unavailable: "unavailable"
        case .verificationFailed: "verification_failed"
        case .versionSkew: "version_skew"
        case nil: "approved"
        }
    }
}

/// The CLI on disk and the root-owned verifier copy disagree on version; the
/// fix is always a re-install, so the message says so.
public struct VersionSkewError: Error, Sendable {
    public let clientVersion: String
    public let verifierVersion: String

    public init(clientVersion: String, verifierVersion: String) {
        self.clientVersion = clientVersion
        self.verifierVersion = verifierVersion
    }

    public var message: String {
        "cc-sudo \(clientVersion) does not match the installed verifier \(verifierVersion); run 'cc-sudo install'"
    }
}
