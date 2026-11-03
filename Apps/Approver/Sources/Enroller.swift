import CCSudoPhone
import Foundation
import Network

/// The phone's half of `sudo cc-sudo trust --phone`: one TCP connection to the
/// address the QR code names, over the tailnet. The phone commits, takes the
/// Mac's nonce, reveals, shows the confirmation code, and waits until the human
/// has typed it at the Mac.
struct Enroller {
    enum EnrollError: Error, LocalizedError {
        case refused(String)
        case connection(String)
        case unexpected(EnrollmentReply.Status)

        var errorDescription: String? {
            switch self {
            case let .refused(detail): "The Mac refused enrollment: \(detail)"
            case let .connection(detail): "Could not reach the Mac over Tailscale: \(detail)"
            case let .unexpected(status): "The Mac answered \(status.rawValue) out of turn."
            }
        }
    }

    let offer: EnrollmentOffer
    let reveal: EnrollmentReveal

    func run(onReceived: @MainActor @Sendable (_ confirmation: String) -> Void) async throws {
        guard let port = NWEndpoint.Port(rawValue: offer.port) else {
            throw EnrollError.connection("bad port \(offer.port)")
        }
        let connection = NWConnection(host: NWEndpoint.Host(offer.address), port: port, using: .tcp)
        defer { connection.cancel() }
        connection.start(queue: .global())
        let commitment = EnrollmentCommitment(code: offer.code, commitment: reveal.commitment)
        try await send(JSONEncoder().encode(commitment) + Data([0x0A]), on: connection)
        var buffer = Data()
        var confirmation: String?
        while true {
            let (line, rest) = try await nextLine(on: connection, buffer: buffer)
            buffer = rest
            let reply = try JSONDecoder().decode(EnrollmentReply.self, from: line)
            switch (reply.status, reply.macNonce, confirmation) {
            case let (.challenge, macNonce?, nil):
                confirmation = ConfirmationCode.of(code: offer.code, mac: offer.mac, reveal: reveal, macNonce: macNonce)
                try await send(JSONEncoder().encode(reveal) + Data([0x0A]), on: connection)
            case let (.received, _, code?):
                await onReceived(code)
            case (.enrolled, _, _?):
                return
            case (.refused, _, _):
                throw EnrollError.refused(reply.detail ?? "no reason given")
            default:
                throw EnrollError.unexpected(reply.status)
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
