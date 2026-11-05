/// Whether a CLI may drive a root-owned verifier, from their two versions. A
/// verifier refuses an older CLI; a CLI refuses a verifier below its floor.
public enum VerifierCompatibility: Equatable, Sendable {
    case current
    case verifierBehind
    case clientBehind
    case incompatible

    /// The oldest verifier this CLI can drive. Raise it to the release being
    /// cut when the `exec` command line changes or when the release fixes a
    /// verifier defect that must not keep running: every older verifier then
    /// exits 106 until `sudo cc-sudo install`.
    public static let minimumVerifier = "0.15.0"

    public init(client: String, verifier: String, minimumVerifier: String = Self.minimumVerifier) {
        guard client != verifier else {
            self = .current
            return
        }
        guard let clientRelease = ReleaseVersion(client),
              let verifierRelease = ReleaseVersion(verifier),
              let floor = ReleaseVersion(minimumVerifier),
              clientRelease != verifierRelease
        else {
            self = .incompatible
            return
        }
        if clientRelease < verifierRelease {
            self = .clientBehind
        } else if verifierRelease < floor {
            self = .incompatible
        } else {
            self = .verifierBehind
        }
    }

    public var allowsRun: Bool {
        self == .current || self == .verifierBehind
    }
}

struct ReleaseVersion: Comparable {
    let major: Int
    let minor: Int
    let patch: Int

    init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        let numbers = parts.compactMap { part in
            let isDigits = part.utf8.allSatisfy { (0x30 ... 0x39).contains($0) }
            return isDigits && (part == "0" || part.first != "0") ? Int(part) : nil
        }
        guard parts.count == 3, numbers.count == 3 else { return nil }
        major = numbers[0]
        minor = numbers[1]
        patch = numbers[2]
    }

    static func < (lhs: Self, rhs: Self) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }
}
