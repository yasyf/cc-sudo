import DaemonKit
import Foundation

/// The consent.request params of synckit's exact v1 RPC contract.
public struct SynckitConsentParams: Codable, Sendable {
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
public struct SynckitAttestation: Codable, Sendable {
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
public struct SynckitConsentResult: Codable, Sendable {
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

/// A source of signed consent results from synckit.
public protocol SynckitConsentClient: Sendable {
    func requestConsent(_ params: SynckitConsentParams) async throws -> SynckitConsentResult
}

/// An exact persistent DaemonKit v1 client for synckit's local RPC service.
public final class SynckitClient: SynckitConsentClient, @unchecked Sendable {
    public enum ClientError: Error, Sendable, CustomStringConvertible {
        case unavailable(String)
        case deadlineExceeded
        case protocolViolation(String)
        case rpc(String)

        public var description: String {
            switch self {
            case let .unavailable(detail):
                "synckitd unavailable: \(detail)"
            case .deadlineExceeded:
                "synckitd consent deadline exceeded"
            case let .protocolViolation(detail):
                "synckitd protocol violation: \(detail)"
            case let .rpc(detail):
                "synckitd RPC failed: \(detail)"
            }
        }
    }

    public static let wireBuild = "synckit.rpc.v1"
    public static let operation = "synckit.rpc.call"
    public static let maximumFrameBytes = 16 * 1024 * 1024
    public static let readDeadline: TimeInterval = 11 * 60

    /// The consent socket for a user: ~/.config/synckit/rpc.sock under their
    /// passwd home directory.
    public static func socketPath(home: URL) -> String {
        home.appending(components: ".config", "synckit", "rpc.sock").path()
    }

    public let socketPath: String
    let deadline: TimeInterval

    private let session = SynckitSession()

    public init(socketPath: String, deadline: TimeInterval = SynckitClient.readDeadline) {
        self.socketPath = socketPath
        self.deadline = deadline
    }

    deinit {
        let session = session
        Task { await session.abort() }
    }

    /// Sends one consent.request and returns its signed result.
    public func requestConsent(_ params: SynckitConsentParams) async throws -> SynckitConsentResult {
        let payload = try Self.encode(params)
        let client: SocketClient
        do {
            client = try await session.current(socketPath: socketPath, deadline: deadline)
        } catch let error as CancellationError {
            throw error
        } catch {
            throw Self.classify(error)
        }

        let terminal: SocketTerminal
        do {
            terminal = try await client.call(
                operation: Self.operation,
                payload: payload,
                deadline: Date().addingTimeInterval(deadline)
            )
        } catch let error as CancellationError {
            throw error
        } catch {
            await session.retire(client)
            throw Self.classify(error)
        }
        return try Self.decode(terminal)
    }

    private static func encode(_ params: SynckitConsentParams) throws -> Data {
        do {
            return try JSONEncoder().encode(SynckitEnvelope(method: "consent.request", params: params))
        } catch {
            throw ClientError.protocolViolation("encode request: \(error)")
        }
    }

    private static func decode(_ terminal: SocketTerminal) throws -> SynckitConsentResult {
        if terminal.rejected {
            throw ClientError.protocolViolation(terminal.reason ?? "request rejected without a reason")
        }
        if let error = terminal.error {
            if error == "context deadline exceeded" {
                throw ClientError.deadlineExceeded
            }
            throw ClientError.rpc(error)
        }
        guard let responsePayload = terminal.payload else {
            throw ClientError.protocolViolation("response carried no payload")
        }

        let reply: SynckitReply
        do {
            reply = try JSONDecoder().decode(SynckitReply.self, from: responsePayload)
        } catch {
            throw ClientError.protocolViolation("decode response: \(error)")
        }
        guard reply.accepted else {
            throw ClientError.rpc(reply.error ?? "unspecified RPC error")
        }
        guard let result = reply.result else {
            throw ClientError.protocolViolation("successful response carried no result")
        }
        return result
    }

    /// Performs the exact DaemonKit handshake without dispatching a request.
    public func probe() async -> Bool {
        do {
            _ = try await session.current(socketPath: socketPath, deadline: deadline)
            return true
        } catch {
            return false
        }
    }

    /// Closes the persistent session and lets a later call reconnect.
    public func close() async {
        await session.close()
    }

    private static func classify(_ error: any Error) -> ClientError {
        guard let transport = error as? SessionTransportError else {
            return .protocolViolation(String(describing: error))
        }
        switch transport {
        case let .systemCall(operation, number):
            return .unavailable("\(operation) failed with errno \(number)")
        case .disconnected:
            return .unavailable("session disconnected")
        case .truncatedFrame, .frameTooLarge, .invalidFrame, .unsupportedProtocolVersion,
             .handshake, .duplicateRequestID, .streamSequence, .cancellationDidNotSettle:
            return .protocolViolation(String(describing: transport))
        }
    }
}

private actor SynckitSession {
    private enum State {
        case idle
        case connecting(UUID, Task<SocketClient, Error>)
        case ready(SocketClient)
    }

    private var state = State.idle

    func current(socketPath: String, deadline: TimeInterval) async throws -> SocketClient {
        switch state {
        case let .ready(client):
            return client
        case let .connecting(id, task):
            return try await finishConnection(id: id, task: task)
        case .idle:
            let id = UUID()
            let task = Task<SocketClient, Error> {
                try await SocketClient(
                    path: socketPath,
                    wireBuild: SynckitClient.wireBuild,
                    configuration: .init(
                        maximumFrameBytes: SynckitClient.maximumFrameBytes,
                        handshakeTimeout: min(deadline, 10),
                        writeTimeout: min(deadline, 10)
                    ),
                    trust: .sameEffectiveUser
                )
            }
            state = .connecting(id, task)
            return try await finishConnection(id: id, task: task)
        }
    }

    func retire(_ failed: SocketClient) async {
        guard case let .ready(active) = state, active === failed else {
            return
        }
        state = .idle
        failed.abort()
    }

    func close() async {
        let previous = state
        state = .idle
        switch previous {
        case let .ready(client):
            await client.close()
        case let .connecting(_, task):
            task.cancel()
            if case let .success(client) = await task.result {
                await client.close()
            }
        case .idle:
            break
        }
    }

    func abort() async {
        let previous = state
        state = .idle
        switch previous {
        case let .ready(client):
            client.abort()
        case let .connecting(_, task):
            task.cancel()
            if case let .success(client) = await task.result {
                client.abort()
            }
        case .idle:
            break
        }
    }

    private func finishConnection(
        id: UUID,
        task: Task<SocketClient, Error>
    ) async throws -> SocketClient {
        do {
            let opened = try await task.value
            switch state {
            case let .connecting(currentID, _) where currentID == id:
                state = .ready(opened)
                return opened
            case let .ready(current) where current === opened:
                return opened
            default:
                await opened.close()
                throw CancellationError()
            }
        } catch {
            if case let .connecting(currentID, _) = state, currentID == id {
                state = .idle
            }
            throw error
        }
    }
}

struct SynckitBridgeClient: SynckitConsentClient {
    static let sudo = "/usr/bin/sudo"

    let socketPath: String
    let userID: uid_t?
    let runner: any ProcessRunner

    init(socketPath: String, userID: uid_t?, runner: any ProcessRunner = LiveProcessRunner()) {
        self.socketPath = socketPath
        self.userID = userID
        self.runner = runner
    }

    func requestConsent(_ params: SynckitConsentParams) async throws -> SynckitConsentResult {
        guard let userID else {
            throw SynckitClient.ClientError.unavailable("no invoking user")
        }
        let input = try JSONEncoder().encode(params)
        let response: SubprocessResult
        do {
            response = try await runner.run(
                executable: Self.sudo,
                arguments: [
                    "-u", "#\(userID)", "-H", RunClient.verifierPath,
                    "synckit-bridge", "--socket", socketPath,
                ],
                stdin: input,
                environment: nil
            )
        } catch {
            throw SynckitClient.ClientError.unavailable("bridge launch failed: \(error)")
        }
        switch response.exitCode {
        case 0:
            do {
                return try JSONDecoder().decode(SynckitConsentResult.self, from: response.stdout)
            } catch {
                throw SynckitClient.ClientError.protocolViolation("bridge response: \(error)")
            }
        case 2:
            throw SynckitClient.ClientError.unavailable(response.stderr.utf8Lossy)
        default:
            throw SynckitClient.ClientError.protocolViolation(
                "bridge exited \(response.exitCode): \(response.stderr.utf8Lossy)"
            )
        }
    }
}
