import Foundation

/// This host's mesh identity for routed verification — the `requested_from`
/// value a peer's helper folds into the SIGNED subject when approving on our
/// behalf. The verifier recomputes with the value from this ROOT-OWNED file
/// (never from user-level synckitd, which an attacker could steer), so a
/// spoofed provenance label fails verification.
///
/// `cc-sudo install` writes it; it MUST match the mesh name the local synckitd
/// advertises as itself (`synckitd status` → `self:`), or routed and
/// synckitd-local approvals fail closed. `cc-sudo doctor` surfaces the value.
public enum OriginIdentity {
    public static let path = "/etc/cc-sudo/origin-host"

    public enum OriginError: Error, Sendable {
        case unconfigured(path: String)
    }

    public static func read(from path: String = path) throws -> String {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw OriginError.unconfigured(path: path)
        }
        let identity = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !identity.isEmpty else {
            throw OriginError.unconfigured(path: path)
        }
        return identity
    }

    /// The install-time default: the short host name.
    public static func defaultIdentity() -> String {
        var buffer = [UInt8](repeating: 0, count: 256)
        buffer.withUnsafeMutableBytes { raw in
            _ = gethostname(raw.baseAddress?.assumingMemoryBound(to: CChar.self), raw.count)
        }
        let full = Data(buffer.prefix(while: { $0 != 0 })).utf8Lossy
        return full.split(separator: ".").first.map(String.init) ?? full
    }
}
