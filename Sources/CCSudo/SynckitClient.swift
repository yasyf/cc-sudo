import Foundation
import os

/// An ndjson unix-socket client for synckitd's frozen consent wire contract:
/// one `{"method":…,"params":…}` line out, one `{"ok":…}` line back. The read
/// deadline is 11 minutes — synckitd's rpc.DispatchTimeout is 10, and a human
/// may sit on the Touch ID sheet for most of it.
/// The consent.request params of the frozen wire contract.
public struct SynckitConsentParams: Encodable, Sendable {
    public let client: String
    public let reason: String
    public let subject: String
    public let argv: [String]
    public let nonce: String
    public let ttlMS: Int
    public let localOnly: Bool

    enum CodingKeys: String, CodingKey {
        case client
        case reason
        case subject
        case argv
        case nonce
        case ttlMS = "ttl_ms"
        case localOnly = "local_only"
    }
}

/// The attestation extension of an approved consent result.
public struct SynckitAttestation: Decodable, Sendable {
    public let keyID: String
    public let sig: String
    public let signedBy: String

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case sig
        case signedBy = "signed_by"
    }
}

/// The consent.request result payload.
public struct SynckitConsentResult: Decodable, Sendable {
    public let verdict: String
    public let approvedBy: String?
    public let routed: Bool?
    public let attestation: SynckitAttestation?

    enum CodingKeys: String, CodingKey {
        case verdict
        case approvedBy = "approved_by"
        case routed
        case attestation
    }
}

struct SynckitEnvelope: Encodable {
    let method: String
    let params: SynckitConsentParams
}

struct SynckitReply: Decodable {
    let accepted: Bool
    let result: SynckitConsentResult?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case accepted = "ok"
        case result
        case error
    }
}

public struct SynckitClient: Sendable {
    public enum ClientError: Error, Sendable {
        case socketUnavailable(path: String, errno: Int32)
        case writeFailed(errno: Int32)
        case readFailed(errno: Int32)
        case deadlineExceeded
        case malformedReply(String)
        case rpc(String)
    }

    public static let readDeadline: TimeInterval = 11 * 60

    /// The consent socket for a user: ~/.config/synckit/rpc.sock under their
    /// passwd home directory.
    public static func socketPath(home: URL) -> String {
        home.appending(components: ".config", "synckit", "rpc.sock").path()
    }

    public let socketPath: String
    let deadline: TimeInterval

    public init(socketPath: String, deadline: TimeInterval = SynckitClient.readDeadline) {
        self.socketPath = socketPath
        self.deadline = deadline
    }

    /// Sends one consent.request and returns the parsed result. Blocking I/O
    /// runs off the cooperative pool.
    public func requestConsent(_ params: SynckitConsentParams) async throws -> SynckitConsentResult {
        let line = try JSONEncoder().encode(SynckitEnvelope(method: "consent.request", params: params))
        let replyLine = try await Task.detached { [socketPath, deadline] in
            try Self.roundTrip(line: line, socketPath: socketPath, deadline: deadline)
        }.value
        let reply: SynckitReply
        do {
            reply = try JSONDecoder().decode(SynckitReply.self, from: replyLine)
        } catch {
            throw ClientError.malformedReply(replyLine.prefix(256).utf8Lossy)
        }
        guard reply.accepted else {
            throw ClientError.rpc(reply.error ?? "unspecified rpc error")
        }
        guard let result = reply.result else {
            throw ClientError.malformedReply("ok reply carried no result")
        }
        return result
    }

    /// Quick reachability probe for doctor: can the socket be connected at all?
    public func probe() -> Bool {
        guard let descriptor = try? Self.connect(socketPath: socketPath, deadline: 2) else { return false }
        close(descriptor)
        return true
    }

    static func connect(socketPath: String, deadline: TimeInterval) throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw ClientError.socketUnavailable(path: socketPath, errno: errno)
        }

        var timeout = timeval(
            tv_sec: Int(deadline),
            tv_usec: Int32((deadline - deadline.rounded(.down)) * 1_000_000)
        )
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path) - 1
        guard pathBytes.count <= capacity else {
            close(descriptor)
            throw ClientError.socketUnavailable(path: socketPath, errno: ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            let savedErrno = errno
            close(descriptor)
            throw ClientError.socketUnavailable(path: socketPath, errno: savedErrno)
        }
        return descriptor
    }

    static func roundTrip(line: Data, socketPath: String, deadline: TimeInterval) throws -> Data {
        let descriptor = try connect(socketPath: socketPath, deadline: deadline)
        defer { close(descriptor) }

        var outgoing = line
        outgoing.append(0x0A)
        try outgoing.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            var remaining = raw
            while !remaining.isEmpty {
                let written = write(descriptor, remaining.baseAddress, remaining.count)
                guard written > 0 else { throw ClientError.writeFailed(errno: errno) }
                remaining = UnsafeRawBufferPointer(rebasing: remaining.dropFirst(written))
            }
        }

        var reply = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = read(descriptor, &buffer, buffer.count)
            if count > 0 {
                reply.append(contentsOf: buffer[0 ..< count])
                if let newline = reply.firstIndex(of: 0x0A) {
                    return reply.prefix(upTo: newline)
                }
            } else if count == 0 {
                guard reply.isEmpty else { return reply }
                throw ClientError.malformedReply("connection closed before a reply line")
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                throw ClientError.deadlineExceeded
            } else {
                throw ClientError.readFailed(errno: errno)
            }
        }
    }
}
