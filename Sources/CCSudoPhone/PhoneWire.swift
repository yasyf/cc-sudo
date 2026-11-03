import AuthKitSubject
import CryptoKit
import Foundation

/// What `sudo cc-sudo trust --phone` draws as a QR code: the Mac's mesh
/// identity (the origin host the phone signs), its tailnet name and address,
/// the one-shot enrollment port, and a one-time code the phone must echo.
public struct EnrollmentOffer: Codable, Sendable, Equatable {
    public static let version = 1

    public let version: Int
    public let mac: String
    public let host: String
    public let address: String
    public let port: UInt16
    public let code: String

    public init(mac: String, host: String, address: String, port: UInt16, code: String) {
        version = Self.version
        self.mac = mac
        self.host = host
        self.address = address
        self.port = port
        self.code = code
    }
}

/// The phone's one JSON line to the enrolling sudo process: the offer's code,
/// its Secure Enclave public key (base64 X9.63), and its APNs device token.
public struct EnrollmentSubmission: Codable, Sendable, Equatable {
    public let code: String
    public let publicKey: String
    public let pushToken: String

    enum CodingKeys: String, CodingKey {
        case code
        case publicKey = "public_key"
        case pushToken = "push_token"
    }

    public init(code: String, publicKey: String, pushToken: String) {
        self.code = code
        self.publicKey = publicKey
        self.pushToken = pushToken
    }
}

/// The sudo process's JSON lines back: `received` once it holds the key and
/// waits for the typed confirmation code, then `enrolled` or `refused`.
public struct EnrollmentReply: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case received
        case enrolled
        case refused
    }

    public let status: Status
    public let detail: String?

    public init(status: Status, detail: String? = nil) {
        self.status = status
        self.detail = detail
    }
}

/// The six digits the phone shows and the human types at the Mac, so the key
/// the Mac enrolls is the key on the phone in their hand.
public enum ConfirmationCode {
    public static func of(publicKey: Data) -> String {
        let digest = Array(SHA256.hash(data: publicKey))
        let value = digest.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return String(format: "%06u", value % 1_000_000)
    }
}

/// A request synckitd parks for the phone, fetched over the tailnet once a
/// push names its id. Only `argv` and `nonce` reach the signature; the phone
/// signs with the Mac name it recorded at enrollment, never one fetched here.
public struct PendingApproval: Codable, Sendable, Equatable {
    public let id: String
    public let argv: [String]
    public let nonce: String

    public init(id: String, argv: [String], nonce: String) {
        self.id = id
        self.argv = argv
        self.nonce = nonce
    }
}

/// The phone's answer to one parked request. A denial carries no signature
/// and is final; an approval carries the key id and the DER ECDSA signature.
public struct ApprovalAnswer: Codable, Sendable, Equatable {
    public enum Verdict: String, Codable, Sendable {
        case approved
        case denied
    }

    public let id: String
    public let nonce: String
    public let verdict: Verdict
    public let keyID: String?
    public let sig: String?

    enum CodingKeys: String, CodingKey {
        case id, nonce, verdict, sig
        case keyID = "key_id"
    }

    public init(id: String, nonce: String, verdict: Verdict, keyID: String? = nil, sig: String? = nil) {
        self.id = id
        self.nonce = nonce
        self.verdict = verdict
        self.keyID = keyID
        self.sig = sig
    }
}

/// The bytes the phone's Secure Enclave key signs: the same nonce ‖ subject a
/// Mac peer signs, with the enrolled Mac's name as the origin host.
public enum PhoneSignature {
    public static func message(nonce: Data, argv: [String], mac: String) -> Data {
        Attestation.message(nonce: nonce, subject: Subject.digest(argv: argv, originHost: mac))
    }
}

/// Commands that run a script or write their input as root, which the phone
/// shows under a warning band. A command outside this list is not safe for
/// that reason alone: env, xargs, and find -exec can run anything too.
public enum ScriptRunner {
    static let runners: Set<String> = [
        "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish",
        "python", "python3", "perl", "ruby", "node", "php", "tclsh", "swift",
        "osascript", "tee",
    ]

    public static func runsScript(_ argv: [String]) -> Bool {
        guard let first = argv.first else { return false }
        let name = String(first.split(separator: "/").last ?? "")
        return runners.contains(name) || name.hasPrefix("python3.")
    }
}

extension PendingApproval {
    /// Where the asking Mac's synckitd serves a parked request on its tailnet
    /// listener: GET fetches it, POST takes the phone's ApprovalAnswer.
    public static func path(id: String) -> String {
        "/cc-sudo/phone/requests/\(id)"
    }
}
