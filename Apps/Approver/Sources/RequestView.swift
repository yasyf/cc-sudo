import AuthKitSubject
import CCSudoPhone
import SwiftUI

/// One parked request, drawn from what the Mac serves and nothing else: every
/// argument in full on its own row, cleaned of control and direction
/// characters, and the argv digest. Approve unlocks only after the last row
/// has scrolled into view, and spends one Face ID match on one signature.
struct RequestView: View {
    enum Phase {
        case loading
        case ready(PendingApproval)
        case answering
        case answered(String)
        case failed(String)
    }

    let model: ApproverModel
    let route: Route
    @State private var phase = Phase.loading
    @State private var readToEnd = false

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(route.mac.mac)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    Button("Close") { model.route = nil }
                }
        }
        .task { await load() }
    }

    @ViewBuilder private var content: some View {
        switch phase {
        case .loading:
            ProgressView("Fetching the request from \(route.mac.mac)…")
        case let .ready(request):
            ready(request)
        case .answering:
            ProgressView("Sending your answer…")
        case let .answered(text):
            Text(text).padding()
        case let .failed(detail):
            Text(detail).foregroundStyle(.red).padding()
        }
    }

    private func ready(_ request: PendingApproval) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 12) {
                    Text("\(route.mac.mac) asks to run this as root:").font(.headline)
                    if ScriptRunner.runsScript(request.argv) {
                        Label(
                            "This runs a script or writes its input as root. Read every argument.",
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .padding()
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.orange.opacity(0.25), in: .rect(cornerRadius: 8))
                    }
                    ForEach(Array(request.argv.enumerated()), id: \.offset) { index, argument in
                        HStack(alignment: .firstTextBaseline) {
                            Text("\(index)").font(.caption.monospaced()).foregroundStyle(.secondary)
                            Text(Subject.sanitized(argument)).font(.body.monospaced()).textSelection(.enabled)
                        }
                    }
                    Text("sha256 \(Subject.argvDigestHex(argv: request.argv))")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.secondary)
                        .onAppear { readToEnd = true }
                }
                .padding()
            }
            HStack {
                Button("Deny", role: .destructive) { Task { await answer(request, approve: false) } }
                    .buttonStyle(.bordered)
                Spacer()
                Button("Approve with Face ID") { Task { await answer(request, approve: true) } }
                    .buttonStyle(.borderedProminent)
                    .disabled(!readToEnd)
            }
            .padding()
        }
    }

    private func load() async {
        do {
            phase = try await .ready(ApprovalClient(route: route).fetch())
        } catch {
            phase = .failed("Could not fetch the request from \(route.mac.host): \(error.localizedDescription) Is Tailscale on?")
        }
    }

    private func answer(_ request: PendingApproval, approve: Bool) async {
        phase = .answering
        do {
            let answer: ApprovalAnswer
            if approve {
                guard let nonce = Data(base64Encoded: request.nonce) else {
                    phase = .failed("The Mac sent a malformed nonce; nothing was signed.")
                    return
                }
                let message = PhoneSignature.message(nonce: nonce, argv: request.argv, mac: route.mac.mac)
                let signature = try await SigningKey.approve(message, reason: "Run \(request.argv.first ?? "") as root on \(route.mac.mac)")
                answer = try ApprovalAnswer(
                    id: request.id,
                    nonce: request.nonce,
                    verdict: .approved,
                    keyID: Attestation.keyID(publicKey: SigningKey.publicKey(.approver)),
                    sig: signature.base64EncodedString()
                )
            } else {
                answer = ApprovalAnswer(id: request.id, nonce: request.nonce, verdict: .denied)
            }
            try await ApprovalClient(route: route).post(answer)
            phase = .answered(approve ? "Approved. The command runs on \(route.mac.mac)." : "Denied. Nothing runs.")
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }
}
