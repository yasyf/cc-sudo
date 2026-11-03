import AuthKit
import CCSudoPhone
import Foundation
import os

/// A tailnet node as `tailscale whois` names it: the stable node id the Mac
/// hands parked requests to, its MagicDNS name, and its OS.
public struct TailnetDevice: Sendable, Equatable {
    public let nodeID: String
    public let name: String
    public let os: String

    public init(nodeID: String, name: String, os: String) {
        self.nodeID = nodeID
        self.name = name
        self.os = os
    }
}

/// A phone approver's root-owned routing record at
/// /etc/cc-sudo/trusted/phones/<name>.json: synckitd pushes to `pushToken`,
/// and serves a parked request only to the tailnet node `nodeID` when the
/// request is signed by `transportKey`. Its signing key is
/// `peers/<name>.pub`, enrolled exactly as a Mac peer's.
public struct PhoneRecord: Codable, Sendable, Equatable {
    public let name: String
    public let nodeID: String
    public let device: String
    public let pushToken: String
    public let transportKey: String
    public let keyID: String

    enum CodingKeys: String, CodingKey {
        case name, device
        case nodeID = "node_id"
        case pushToken = "push_token"
        case transportKey = "transport_key"
        case keyID = "key_id"
    }
}

/// One `trust --phone` session. The first iPhone that echoes the offer's
/// one-time code commits to its keys; the Mac answers with a fresh nonce; the
/// phone reveals what it committed to; the human types the confirmation code
/// the phone shows. Any device that is not an iPhone, a second device echoing
/// the code, or a reveal that breaks its commitment ends the session.
public struct PhoneEnrollment: Sendable {
    public enum EnrollmentError: Error, Sendable, Equatable {
        case notAPhone(device: String, os: String)
        case secondDevice(device: String)
        case wrongDevice(device: String)
        case commitmentMismatch
        case malformedKey(String)
        case confirmationMismatch
        case noPhone
    }

    struct Committed: Sendable {
        let device: TailnetDevice
        let commitment: String
        let macNonce: String
        var reveal: EnrollmentReveal?
    }

    let name: String
    let mac: String
    let code: String
    let makeNonce: @Sendable () throws -> Data
    private(set) var committed: Committed?

    public init(
        name: String,
        mac: String,
        code: String,
        makeNonce: @escaping @Sendable () throws -> Data = { try Nonce.generate() }
    ) throws {
        try TrustStore.validatePeerName(name)
        self.name = name
        self.mac = mac
        self.code = code
        self.makeNonce = makeNonce
    }

    /// A fresh 128-bit one-time code, base64url.
    public static func newCode() throws -> String {
        try Nonce.generate().prefix(16).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Takes a commitment from `device` and returns the Mac's nonce for it,
    /// or nil for a wrong code, which the caller refuses while it keeps
    /// listening; throws when the session must end.
    public mutating func commit(_ commitment: EnrollmentCommitment, from device: TailnetDevice) throws -> String? {
        guard Self.constantTimeEqual(commitment.code, code) else { return nil }
        guard device.os == "iOS" else { throw EnrollmentError.notAPhone(device: device.name, os: device.os) }
        guard committed == nil else { throw EnrollmentError.secondDevice(device: device.name) }
        let macNonce = try makeNonce().base64EncodedString()
        committed = Committed(device: device, commitment: commitment.commitment, macNonce: macNonce)
        return macNonce
    }

    /// Takes the committed device's reveal and returns the device to name to
    /// the human.
    public mutating func reveal(_ reveal: EnrollmentReveal, from device: TailnetDevice) throws -> TailnetDevice {
        guard var held = committed, held.reveal == nil else { throw EnrollmentError.noPhone }
        guard held.device == device else { throw EnrollmentError.wrongDevice(device: device.name) }
        guard Self.constantTimeEqual(reveal.commitment, held.commitment) else { throw EnrollmentError.commitmentMismatch }
        for key in [reveal.publicKey, reveal.transportKey] {
            guard let bytes = Data(base64Encoded: key), (try? Attestation.publicKey(fromX963: bytes)) != nil else {
                throw EnrollmentError.malformedKey(device.name)
            }
        }
        held.reveal = reveal
        committed = held
        return device
    }

    /// Checks the typed confirmation code against the whole exchange and
    /// returns what to enroll.
    public func confirm(typed: String) throws -> (record: PhoneRecord, publicKey: Data) {
        guard let held = committed, let reveal = held.reveal, let publicKey = Data(base64Encoded: reveal.publicKey) else {
            throw EnrollmentError.noPhone
        }
        let expected = ConfirmationCode.of(code: code, mac: mac, reveal: reveal, macNonce: held.macNonce)
        guard typed.trimmingCharacters(in: .whitespacesAndNewlines) == expected else {
            throw EnrollmentError.confirmationMismatch
        }
        let record = PhoneRecord(
            name: name,
            nodeID: held.device.nodeID,
            device: held.device.name,
            pushToken: reveal.pushToken,
            transportKey: reveal.transportKey,
            keyID: Attestation.keyID(publicKey: publicKey)
        )
        return (record, publicKey)
    }

    static func constantTimeEqual(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        guard left.count == right.count else { return false }
        return zip(left, right).reduce(UInt8(0)) { $0 | ($1.0 ^ $1.1) } == 0
    }
}

extension TrustStore {
    /// Writes a confirmed phone's key beside the Mac peers' and its routing
    /// record, both root-owned and world-readable.
    public func enroll(phone record: PhoneRecord, publicKey: Data) throws {
        for directory in [peersDirectory, phonesDirectory] {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o755]
            )
        }
        let keyURL = try peerKeyURL(host: record.name)
        try Data((publicKey.base64EncodedString() + "\n").utf8).write(to: keyURL)
        let recordURL = try phoneRecordURL(name: record.name)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(record).write(to: recordURL)
        for url in [keyURL, recordURL] {
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path())
        }
        Logger.trust.info("enrolled phone \(record.name, privacy: .public) node \(record.nodeID, privacy: .public) key \(record.keyID, privacy: .public)")
    }
}
