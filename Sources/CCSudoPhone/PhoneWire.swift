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

/// The phone's first JSON line: the offer's one-time code and a commitment
/// to everything it will reveal, sent before it sees the Mac's nonce, so a
/// relay cannot grind a key whose confirmation code matches.
public struct EnrollmentCommitment: Codable, Sendable, Equatable {
    public let code: String
    public let commitment: String

    public init(code: String, commitment: String) {
        self.code = code
        self.commitment = commitment
    }
}

/// The phone's second JSON line, once the Mac has sent its nonce: its signing
/// key (Face ID, base64 X9.63), its transport key (no biometry; it
/// authenticates fetches and answers), its APNs token, and the committed nonce.
public struct EnrollmentReveal: Codable, Sendable, Equatable {
    public let publicKey: String
    public let transportKey: String
    public let pushToken: String
    public let nonce: String

    enum CodingKeys: String, CodingKey {
        case nonce
        case publicKey = "public_key"
        case transportKey = "transport_key"
        case pushToken = "push_token"
    }

    public init(publicKey: String, transportKey: String, pushToken: String, nonce: String) {
        self.publicKey = publicKey
        self.transportKey = transportKey
        self.pushToken = pushToken
        self.nonce = nonce
    }

    public var commitment: String {
        Data(SHA256.hash(data: Subject.canonicalEncoding(argv: [publicKey, transportKey, pushToken, nonce])))
            .base64EncodedString()
    }
}

/// The sudo process's JSON lines back: `challenge` with its nonce after a
/// valid commitment, `received` once the reveal matches it, then `enrolled`
/// or `refused`.
public struct EnrollmentReply: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case challenge
        case received
        case enrolled
        case refused
    }

    public let status: Status
    public let macNonce: String?
    public let detail: String?

    enum CodingKeys: String, CodingKey {
        case status, detail
        case macNonce = "mac_nonce"
    }

    public init(status: Status, macNonce: String? = nil, detail: String? = nil) {
        self.status = status
        self.macNonce = macNonce
        self.detail = detail
    }
}

/// The six digits the phone shows and the human types at the Mac: a digest of
/// the whole exchange, so the keys, push token and nonces the Mac enrolls are
/// the ones on the phone in their hand. Because the phone commits before the
/// Mac's nonce is known, a relay matches it with odds of one in a million per
/// enrollment, not by search.
public enum ConfirmationCode {
    public static func of(code: String, mac: String, reveal: EnrollmentReveal, macNonce: String) -> String {
        let transcript = Subject.canonicalEncoding(argv: [
            code, mac, reveal.publicKey, reveal.transportKey, reveal.pushToken, reveal.nonce, macNonce,
        ])
        let value = SHA256.hash(data: transcript).prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
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

/// How the phone authenticates a fetch or an answer to synckitd: an
/// `Authorization: CCSudoPhone <base64 DER signature>` header by its transport
/// key over this message, so a tailnet node that is not the enrolled phone
/// reads no command and posts no answer.
public enum TransportAuth {
    public static let scheme = "CCSudoPhone"

    public static func message(method: String, id: String, body: Data) -> Data {
        Subject.canonicalEncoding(argv: [
            "cc-sudo-phone-v1", method, id, Data(SHA256.hash(data: body)).base64EncodedString(),
        ])
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

public extension PendingApproval {
    /// Where the asking Mac's synckitd serves a parked request on its tailnet
    /// listener: GET fetches it, POST takes the phone's ApprovalAnswer.
    static func path(id: String) -> String {
        "/cc-sudo/phone/requests/\(id)"
    }
}
