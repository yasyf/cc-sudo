import SwiftUI

struct RootView: View {
    @Bindable var model: ApproverModel
    @State private var enrolling = false

    var body: some View {
        NavigationStack {
            List {
                Section("Macs") {
                    if model.macs.isEmpty {
                        Text("No Mac yet. At the Mac, run sudo cc-sudo trust --phone <name>, then tap Enroll.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.macs) { mac in
                        VStack(alignment: .leading) {
                            Text(mac.mac).font(.headline)
                            Text(mac.host).font(.caption.monospaced()).foregroundStyle(.secondary)
                        }
                    }
                }
                if let notice = model.notice {
                    Section { Text(notice).foregroundStyle(.red) }
                }
            }
            .navigationTitle("cc-sudo")
            .toolbar {
                Button("Enroll") { enrolling = true }
            }
            .sheet(isPresented: $enrolling) {
                EnrollView(model: model)
            }
            .fullScreenCover(item: $model.route) { route in
                RequestView(model: model, route: route)
            }
        }
    }
}
