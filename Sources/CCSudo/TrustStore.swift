import AuthKit
import Foundation

/// The root-owned enrolled public keys under /etc/cc-sudo/trusted: `self.pub`
/// for this host's authkit SE key, `peers/<host>.pub` for each host enrolled
/// via `cc-sudo trust`. Files hold the base64 X9.63 key exactly as authkit's
/// keygen emitted it. A missing, stale, or malformed key HARD-FAILS the
/// verify — there is no unsigned fallback anywhere.
public struct TrustStore: Sendable {
    public enum TrustError: Error, Sendable {
        case missingSelfKey(path: String)
        case missingPeerKey(host: String, path: String)
        case malformedKey(path: String, detail: String)
        case invalidPeerName(String)
    }

    public static let defaultDirectory = URL(filePath: "/etc/cc-sudo/trusted", directoryHint: .isDirectory)

    static let peerNameCharacters = CharacterSet(
        charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_@"
    )

    public let directory: URL

    public init(directory: URL = TrustStore.defaultDirectory) {
        self.directory = directory
    }

    public var selfKeyURL: URL {
        directory.appending(component: "self.pub")
    }

    public var peersDirectory: URL {
        directory.appending(component: "peers", directoryHint: .isDirectory)
    }

    public func peerKeyURL(host: String) throws -> URL {
        try Self.validatePeerName(host)
        return peersDirectory.appending(component: "\(host).pub")
    }

    /// A peer name becomes a filename under a root-owned directory, so it must
    /// never traverse: mesh-name characters only ("me@studio", "host-1.local").
    public static func validatePeerName(_ name: String) throws {
        guard !name.isEmpty,
              !name.hasPrefix("."),
              name.unicodeScalars.allSatisfy(peerNameCharacters.contains)
        else {
            throw TrustError.invalidPeerName(name)
        }
    }

    public func selfKey() throws -> Data {
        guard FileManager.default.fileExists(atPath: selfKeyURL.path()) else {
            throw TrustError.missingSelfKey(path: selfKeyURL.path())
        }
        return try key(at: selfKeyURL)
    }

    public func peerKey(host: String) throws -> Data {
        let url = try peerKeyURL(host: host)
        guard FileManager.default.fileExists(atPath: url.path()) else {
            throw TrustError.missingPeerKey(host: host, path: url.path())
        }
        return try key(at: url)
    }

    /// The enrolled peers, by host name.
    public func enrolledPeers() -> [String] {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: peersDirectory.path())) ?? []
        return entries.filter { $0.hasSuffix(".pub") }.map { String($0.dropLast(4)) }.sorted()
    }

    /// Parses and validates one enrolled key file: base64 text → X9.63 bytes
    /// that Security.framework accepts as a P-256 public key.
    public func key(at url: URL) throws -> Data {
        let text: String
        do {
            text = try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw TrustError.malformedKey(path: url.path(), detail: error.localizedDescription)
        }
        guard let bytes = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw TrustError.malformedKey(path: url.path(), detail: "not base64")
        }
        do {
            _ = try Attestation.publicKey(fromX963: bytes)
        } catch {
            throw TrustError.malformedKey(path: url.path(), detail: String(describing: error))
        }
        return bytes
    }
}
