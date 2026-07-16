import AuthKit
import Foundation
import os

/// Routed root of trust: `cc-sudo trust <peer>` fetches the peer's enrolled
/// self key (`/etc/cc-sudo/trusted/self.pub`, written by that host's own
/// install) over ssh and enrolls it root-owned under
/// `/etc/cc-sudo/trusted/peers/<host>.pub`.
///
/// TRUST ASSUMPTION, by design: the ssh channel is trusted ONLY at this
/// enrollment moment, under local admin auth (the command requires root).
/// After enrollment the mesh is pure transport — every routed approval is
/// verified against the key enrolled here, and removing the file hard-fails
/// routed verifies rather than falling back to unsigned.
public struct PeerTrust: Sendable {
    public enum PeerTrustError: Error, Sendable {
        case notRoot
        case fetchFailed(peer: String, exitCode: Int32, stderr: String)
    }

    static let ssh = "/usr/bin/ssh"

    let runner: any ProcessRunner
    let store: TrustStore
    let euid: @Sendable () -> uid_t

    public init(
        runner: any ProcessRunner = LiveProcessRunner(),
        store: TrustStore = TrustStore(),
        euid: @escaping @Sendable () -> uid_t = { geteuid() }
    ) {
        self.runner = runner
        self.store = store
        self.euid = euid
    }

    /// Enrolls `peer`; returns the key ID for display. The fetched bytes must
    /// parse as a P-256 X9.63 public key before anything is written.
    public func trust(peer: String) async throws -> String {
        guard euid() == 0 else { throw PeerTrustError.notRoot }
        try TrustStore.validatePeerName(peer)

        // The "--" end-of-options token stops ssh from reading `peer` as a flag
        // even if validatePeerName's dash guard is ever relaxed — defense in
        // depth on the root-executed ssh spawn.
        let result = try await runner.run(
            executable: Self.ssh,
            arguments: ["-o", "BatchMode=yes", "--", peer, "cat", "/etc/cc-sudo/trusted/self.pub"],
            stdin: nil,
            environment: nil
        )
        guard result.exitCode == 0 else {
            throw PeerTrustError.fetchFailed(
                peer: peer,
                exitCode: result.exitCode,
                stderr: result.stderr.utf8Lossy
            )
        }

        let text = result.stdout.utf8Lossy
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let keyBytes = Data(base64Encoded: text),
              (try? Attestation.publicKey(fromX963: keyBytes)) != nil
        else {
            throw TrustStore.TrustError.malformedKey(path: "ssh:\(peer)", detail: "not a base64 X9.63 P-256 key")
        }

        let url = try store.peerKeyURL(host: peer)
        try FileManager.default.createDirectory(
            at: store.peersDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755]
        )
        try Data((text + "\n").utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path())

        let keyID = Attestation.keyID(publicKey: keyBytes)
        Logger.trust.info("enrolled peer \(peer, privacy: .public) key \(keyID, privacy: .public)")
        return keyID
    }
}
