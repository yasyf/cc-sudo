import CCSudoPhone
import SwiftUI
import VisionKit

struct EnrollView: View {
    enum Phase {
        case scanning
        case connecting
        case confirm(code: String, mac: String)
        case done(String)
        case failed(String)
    }

    let model: ApproverModel
    @Environment(\.dismiss) private var dismiss
    @State private var phase = Phase.scanning

    var body: some View {
        NavigationStack {
            Group {
                switch phase {
                case .scanning:
                    if model.pushToken == nil {
                        Text("Allow notifications for cc-sudo in Settings first: the Mac needs this phone's push address.")
                            .padding()
                    } else {
                        QRScanner { payload in scanned(payload) }
                            .ignoresSafeArea()
                    }
                case .connecting:
                    ProgressView("Reaching the Mac over Tailscale…")
                case let .confirm(code, mac):
                    VStack(spacing: 16) {
                        Text("Type this code at \(mac):")
                        Text(code).font(.system(size: 56, weight: .semibold, design: .monospaced))
                    }
                case let .done(mac):
                    Text("Enrolled with \(mac).")
                case let .failed(detail):
                    Text(detail).foregroundStyle(.red).padding()
                }
            }
            .navigationTitle("Enroll a Mac")
            .toolbar { Button("Close") { dismiss() } }
        }
    }

    private func scanned(_ payload: String) {
        guard case .scanning = phase, let pushToken = model.pushToken else { return }
        let offer: EnrollmentOffer
        do {
            offer = try JSONDecoder().decode(EnrollmentOffer.self, from: Data(payload.utf8))
        } catch {
            phase = .failed("That QR code is not a cc-sudo enrollment code.")
            return
        }
        guard offer.version == EnrollmentOffer.version else {
            phase = .failed("This Mac runs a cc-sudo this app does not speak (offer v\(offer.version)). Update both.")
            return
        }
        phase = .connecting
        Task {
            do {
                let publicKey = try SigningKey.publicKey()
                let submission = EnrollmentSubmission(
                    code: offer.code,
                    publicKey: publicKey.base64EncodedString(),
                    pushToken: pushToken
                )
                try await Enroller(offer: offer, submission: submission).run {
                    phase = .confirm(code: ConfirmationCode.of(publicKey: publicKey), mac: offer.mac)
                }
                try model.enrolled(EnrolledMac(mac: offer.mac, host: offer.host))
                phase = .done(offer.mac)
            } catch {
                phase = .failed(error.localizedDescription)
            }
        }
    }
}

struct QRScanner: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .accurate,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_: DataScannerViewController, context _: Context) {}

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan)
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onScan: (String) -> Void

        init(onScan: @escaping (String) -> Void) {
            self.onScan = onScan
        }

        func dataScanner(_: DataScannerViewController, didAdd items: [RecognizedItem], allItems _: [RecognizedItem]) {
            for case let .barcode(barcode) in items {
                if let payload = barcode.payloadStringValue {
                    onScan(payload)
                }
            }
        }
    }
}
