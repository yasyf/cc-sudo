import CCSudoPhone
import Foundation
import Network

/// The phone's half of `sudo cc-sudo trust --phone`: one TCP connection to the
/// address the QR code names, over the tailnet, carrying one JSON line each way
/// until the human has typed the confirmation code at the Mac.
struct Enroller {
    enum EnrollError: Error, LocalizedError {
        case refused(String)
        case connection(String)

        var errorDescription: String? {
            switch self {
            case let .refused(detail): "The Mac refused enrollment: \(detail)"
            case let .connection(detail): "Could not reach the Mac over Tailscale: \(detail)"
            }
        }
    }

    let offer: EnrollmentOffer
    let submission: EnrollmentSubmission

    func run(onReceived: @MainActor @Sendable () -> Void) async throws {
        guard let port = NWEndpoint.Port(rawValue: offer.port) else {
            throw EnrollError.connection("bad port \(offer.port)")
        }
        let connection = NWConnection(host: NWEndpoint.Host(offer.address), port: port, using: .tcp)
        defer { connection.cancel() }
        connection.start(queue: .global())
        try await send(JSONEncoder().encode(submission) + Data([0x0A]), on: connection)
        var buffer = Data()
        while true {
            let (line, rest) = try await nextLine(on: connection, buffer: buffer)
            buffer = rest
            let reply = try JSONDecoder().decode(EnrollmentReply.self, from: line)
            switch reply.status {
            case .received:
                await onReceived()
            case .enrolled:
                return
            case .refused:
                throw EnrollError.refused(reply.detail ?? "no reason given")
            }
        }
    }

    private func send(_ data: Data, on connection: NWConnection) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: EnrollError.connection(String(describing: error)))
                } else {
                    continuation.resume()
                }
            })
        }
    }

    private func nextLine(on connection: NWConnection, buffer: Data) async throws -> (Data, Data) {
        var buffer = buffer
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                return (buffer[..<newline], buffer[buffer.index(after: newline)...])
            }
            let chunk: Data = try await withCheckedThrowingContinuation { continuation in
                connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, error in
                    if let error {
                        continuation.resume(throwing: EnrollError.connection(String(describing: error)))
                    } else if let data, !data.isEmpty {
                        continuation.resume(returning: data)
                    } else {
                        continuation.resume(throwing: EnrollError.connection("the Mac closed the connection"))
                    }
                }
            }
            buffer += chunk
        }
    }
}
