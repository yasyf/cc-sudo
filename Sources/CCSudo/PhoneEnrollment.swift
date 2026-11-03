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
/// /etc/cc-sudo/trusted/phones/<name>.json: synckitd pushes to `pushToken`
/// and hands a parked request only to the tailnet node `nodeID`. Its key is
/// `peers/<name>.pub`, enrolled exactly as a Mac peer's.
public struct PhoneRecord: Codable, Sendable, Equatable {
    public let name: String
    public let nodeID: String
    public let device: String
    public let pushToken: String
    public let keyID: String

    enum CodingKeys: String, CodingKey {
        case name, device
        case nodeID = "node_id"
        case pushToken = "push_token"
        case keyID = "key_id"
    }
}

/// One `trust --phone` session: it holds the first phone that echoes the
/// offer's one-time code, refuses any device that is not an iPhone, gives up
/// when a second device echoes the code, and enrolls only once the human types
/// the confirmation code the phone shows.
public struct PhoneEnrollment: Sendable {
    public enum EnrollmentError: Error, Sendable, Equatable {
        case notAPhone(device: String, os: String)
        case secondDevice(device: String)
        case malformedKey(String)
        case confirmationMismatch
        case noPhone
    }

    struct Held: Sendable {
        let device: TailnetDevice
        let publicKey: Data
        let pushToken: String
    }

    let name: String
    let code: String
    private(set) var held: Held?

    public init(name: String, code: String) throws {
        try TrustStore.validatePeerName(name)
        self.name = name
        self.code = code
    }

    /// A fresh 128-bit one-time code, base64url.
    public static func newCode() throws -> String {
        try Nonce.generate().prefix(16).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Takes one submission from `device`. Returns false for a wrong code, so
    /// the caller refuses that connection and keeps listening; throws when
    /// the session must end.
    public mutating func receive(_ submission: EnrollmentSubmission, from device: TailnetDevice) throws -> Bool {
        guard Self.constantTimeEqual(submission.code, code) else { return false }
        guard device.os == "iOS" else { throw EnrollmentError.notAPhone(device: device.name, os: device.os) }
        guard let key = Data(base64Encoded: submission.publicKey),
              (try? Attestation.publicKey(fromX963: key)) != nil
        else {
            throw EnrollmentError.malformedKey(device.name)
        }
        if let held {
            guard held.device == device, held.publicKey == key else {
                throw EnrollmentError.secondDevice(device: device.name)
            }
            return true
        }
        held = Held(device: device, publicKey: key, pushToken: submission.pushToken)
        return true
    }

    /// Checks the typed confirmation code against the held phone's key and
    /// returns what to enroll.
    public func confirm(typed: String) throws -> (record: PhoneRecord, publicKey: Data) {
        guard let held else { throw EnrollmentError.noPhone }
        guard typed.trimmingCharacters(in: .whitespacesAndNewlines) == ConfirmationCode.of(publicKey: held.publicKey) else {
            throw EnrollmentError.confirmationMismatch
        }
        let record = PhoneRecord(
            name: name,
            nodeID: held.device.nodeID,
            device: held.device.name,
            pushToken: held.pushToken,
            keyID: Attestation.keyID(publicKey: held.publicKey)
        )
        return (record, held.publicKey)
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
