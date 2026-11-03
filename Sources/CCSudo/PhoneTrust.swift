import CCSudoPhone
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation
import Network

/// `sudo cc-sudo trust --phone <name>`: draws an enrollment QR code, listens
/// once on this Mac's tailnet address for the phone's key, names the device
/// that answered by `tailscale whois`, and enrolls it once the human types
/// the code the phone shows. The sudo process receives the key itself;
/// synckitd never touches enrollment.
public struct PhoneTrust: Sendable {
    public enum PhoneTrustError: Error, Sendable {
        case notRoot
        case tailscaleMissing
        case tailscaleFailed(command: String, stderr: String)
        case noTailnetAddress
        case listenerFailed(String)
        case qrUnavailable
    }

    static let tailscaleCandidates = [
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "/opt/homebrew/bin/tailscale",
        "/usr/local/bin/tailscale",
    ]

    let runner: any ProcessRunner
    let store: TrustStore
    let euid: @Sendable () -> uid_t
    let mac: @Sendable () throws -> String
    let readConfirmation: @Sendable () -> String?

    public init(
        runner: any ProcessRunner = LiveProcessRunner(),
        store: TrustStore = TrustStore(),
        euid: @escaping @Sendable () -> uid_t = { geteuid() },
        mac: @escaping @Sendable () throws -> String = { try OriginIdentity.read() },
        readConfirmation: @escaping @Sendable () -> String? = { readLine() }
    ) {
        self.runner = runner
        self.store = store
        self.euid = euid
        self.mac = mac
        self.readConfirmation = readConfirmation
    }

    public func trust(phone name: String) async throws -> PhoneRecord {
        guard euid() == 0 else { throw PhoneTrustError.notRoot }
        let enrollment = try PhoneEnrollment(name: name, code: PhoneEnrollment.newCode())
        let mac = try mac()
        let tailscale = try Self.locateTailscale()
        let node = try await selfNode(tailscale: tailscale)
        let session = EnrollmentSession(enrollment: enrollment) { address in
            try await whois(tailscale: tailscale, address: address)
        }
        let port = try await session.listen(on: node.address)
        let offer = EnrollmentOffer(mac: mac, host: node.dnsName, address: node.address, port: port, code: enrollment.code)
        try print(TerminalQR.render(JSONEncoder().encode(offer)))
        print("Scan this with the cc-sudo Approver app on your iPhone to enroll it as \(name) on \(mac).")

        let device = try await session.firstPhone()
        print("\(device.name) (\(device.os), tailnet node \(device.nodeID)) answered.")
        print("Type the 6-digit code your phone shows: ", terminator: "")
        let typed = readConfirmation() ?? ""
        do {
            let (record, publicKey) = try await session.confirm(typed: typed)
            try store.enroll(phone: record, publicKey: publicKey)
            await session.finish(EnrollmentReply(status: .enrolled))
            return record
        } catch {
            await session.finish(EnrollmentReply(status: .refused, detail: String(describing: error)))
            throw error
        }
    }

    static func locateTailscale() throws -> String {
        guard let path = tailscaleCandidates.first(where: FileManager.default.isExecutableFile(atPath:)) else {
            throw PhoneTrustError.tailscaleMissing
        }
        return path
    }

    struct SelfNode {
        let dnsName: String
        let address: String
    }

    func selfNode(tailscale: String) async throws -> SelfNode {
        struct Status: Decodable {
            struct Node: Decodable {
                let dnsName: String
                let addresses: [String]

                enum CodingKeys: String, CodingKey {
                    case dnsName = "DNSName"
                    case addresses = "TailscaleIPs"
                }
            }

            let node: Node

            enum CodingKeys: String, CodingKey {
                case node = "Self"
            }
        }
        let status = try await JSONDecoder().decode(Status.self, from: run(tailscale, ["status", "--json"]))
        guard let address = status.node.addresses.first(where: { $0.contains(".") }) else {
            throw PhoneTrustError.noTailnetAddress
        }
        let dnsName = status.node.dnsName.hasSuffix(".") ? String(status.node.dnsName.dropLast()) : status.node.dnsName
        return SelfNode(dnsName: dnsName, address: address)
    }

    func whois(tailscale: String, address: String) async throws -> TailnetDevice {
        struct WhoIs: Decodable {
            struct Node: Decodable {
                struct HostInfo: Decodable {
                    let os: String

                    enum CodingKeys: String, CodingKey {
                        case os = "OS"
                    }
                }

                let stableID: String
                let name: String
                let hostInfo: HostInfo

                enum CodingKeys: String, CodingKey {
                    case stableID = "StableID"
                    case name = "Name"
                    case hostInfo = "Hostinfo"
                }
            }

            let node: Node

            enum CodingKeys: String, CodingKey {
                case node = "Node"
            }
        }
        let who = try await JSONDecoder().decode(WhoIs.self, from: run(tailscale, ["whois", "--json", address]))
        return TailnetDevice(nodeID: who.node.stableID, name: who.node.name, os: who.node.hostInfo.os)
    }

    func run(_ tailscale: String, _ arguments: [String]) async throws -> Data {
        let result = try await runner.run(executable: tailscale, arguments: arguments, stdin: nil, environment: nil)
        guard result.exitCode == 0 else {
            throw PhoneTrustError.tailscaleFailed(
                command: (["tailscale"] + arguments).joined(separator: " "),
                stderr: result.stderr.utf8Lossy
            )
        }
        return result.stdout
    }
}

/// The one-shot listener behind `trust --phone`: every connection sends one
/// JSON line; the first iPhone that echoes the code is held until the human
/// confirms, and any failure ends the session for every waiter.
actor EnrollmentSession {
    static let maxLine = 8192

    private var enrollment: PhoneEnrollment
    private let whois: @Sendable (String) async throws -> TailnetDevice
    private var listener: NWListener?
    private var heldConnection: NWConnection?
    private var failure: (any Error)?
    private var waiters: [CheckedContinuation<TailnetDevice, any Error>] = []

    init(enrollment: PhoneEnrollment, whois: @escaping @Sendable (String) async throws -> TailnetDevice) {
        self.enrollment = enrollment
        self.whois = whois
    }

    func listen(on address: String) async throws -> UInt16 {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(address), port: .any)
        let listener = try NWListener(using: parameters)
        self.listener = listener
        listener.newConnectionHandler = { connection in
            Task { await self.accept(connection) }
        }
        return try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    if let port = listener.port {
                        continuation.resume(returning: port.rawValue)
                    } else {
                        continuation.resume(throwing: PhoneTrust.PhoneTrustError.listenerFailed("ready without a port"))
                    }
                case let .failed(error):
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: PhoneTrust.PhoneTrustError.listenerFailed(String(describing: error)))
                case .cancelled:
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: PhoneTrust.PhoneTrustError.listenerFailed("cancelled"))
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
    }

    func firstPhone() async throws -> TailnetDevice {
        if let failure { throw failure }
        if let held = enrollment.held { return held.device }
        return try await withCheckedThrowingContinuation { waiters.append($0) }
    }

    func confirm(typed: String) throws -> (record: PhoneRecord, publicKey: Data) {
        if let failure { throw failure }
        return try enrollment.confirm(typed: typed)
    }

    func finish(_ reply: EnrollmentReply) async {
        if let heldConnection {
            await Self.send(reply, on: heldConnection)
            heldConnection.cancel()
        }
        listener?.cancel()
    }

    private func accept(_ connection: NWConnection) async {
        connection.start(queue: .global())
        guard failure == nil,
              case let .hostPort(host, _) = connection.endpoint,
              let line = try? await Self.receiveLine(on: connection),
              let submission = try? JSONDecoder().decode(EnrollmentSubmission.self, from: line),
              let device = try? await whois("\(host)")
        else {
            await Self.send(EnrollmentReply(status: .refused), on: connection)
            connection.cancel()
            return
        }
        do {
            guard try enrollment.receive(submission, from: device) else {
                await Self.send(EnrollmentReply(status: .refused, detail: "wrong code"), on: connection)
                connection.cancel()
                return
            }
        } catch {
            fail(error)
            await Self.send(EnrollmentReply(status: .refused, detail: String(describing: error)), on: connection)
            connection.cancel()
            return
        }
        heldConnection?.cancel()
        heldConnection = connection
        await Self.send(EnrollmentReply(status: .received), on: connection)
        let waiting = waiters
        waiters = []
        waiting.forEach { $0.resume(returning: device) }
    }

    private func fail(_ error: any Error) {
        failure = error
        let waiting = waiters
        waiters = []
        waiting.forEach { $0.resume(throwing: error) }
        heldConnection?.cancel()
        listener?.cancel()
    }

    static func receiveLine(on connection: NWConnection, buffer: Data = Data()) async throws -> Data {
        let chunk: Data = try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxLine) { data, _, isComplete, error in
                if let error {
                    continuation.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else {
                    continuation.resume(throwing: PhoneTrust.PhoneTrustError.listenerFailed(isComplete ? "closed" : "empty read"))
                }
            }
        }
        let received = buffer + chunk
        if let newline = received.firstIndex(of: 0x0A) {
            return received[..<newline]
        }
        guard received.count < maxLine else {
            throw PhoneTrust.PhoneTrustError.listenerFailed("line over \(maxLine) bytes")
        }
        return try await receiveLine(on: connection, buffer: received)
    }

    static func send(_ reply: EnrollmentReply, on connection: NWConnection) async {
        guard let line = try? JSONEncoder().encode(reply) else { return }
        await withCheckedContinuation { continuation in
            connection.send(content: line + Data([0x0A]), completion: .contentProcessed { _ in continuation.resume() })
        }
    }
}

/// A QR code drawn in the terminal with half-block characters, black on white
/// whatever the terminal's colors, so a phone camera reads it.
enum TerminalQR {
    static func render(_ payload: Data) throws -> String {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = payload
        filter.correctionLevel = "M"
        guard let image = filter.outputImage,
              let cgImage = CIContext().createCGImage(image, from: image.extent)
        else {
            throw PhoneTrust.PhoneTrustError.qrUnavailable
        }
        let size = cgImage.width
        var pixels = [UInt8](repeating: 255, count: size * size)
        let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
            guard let context = CGContext(
                data: buffer.baseAddress,
                width: size,
                height: size,
                bitsPerComponent: 8,
                bytesPerRow: size,
                space: CGColorSpaceCreateDeviceGray(),
                bitmapInfo: CGImageAlphaInfo.none.rawValue
            ) else {
                return false
            }
            context.draw(cgImage, in: CGRect(x: 0, y: 0, width: size, height: size))
            return true
        }
        guard drawn else { throw PhoneTrust.PhoneTrustError.qrUnavailable }
        let quiet = 2
        func dark(_ x: Int, _ y: Int) -> Bool {
            let (px, py) = (x - quiet, y - quiet)
            guard (0 ..< size).contains(px), (0 ..< size).contains(py) else { return false }
            return pixels[py * size + px] < 128
        }
        let span = size + 2 * quiet
        var rows: [String] = []
        for y in stride(from: 0, to: span, by: 2) {
            var row = "\u{1B}[30;47m"
            for x in 0 ..< span {
                switch (dark(x, y), dark(x, y + 1)) {
                case (true, true): row += "█"
                case (true, false): row += "▀"
                case (false, true): row += "▄"
                case (false, false): row += " "
                }
            }
            rows.append(row + "\u{1B}[0m")
        }
        return rows.joined(separator: "\n")
    }
}
