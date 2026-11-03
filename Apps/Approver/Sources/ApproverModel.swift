import Foundation
import Observation

struct EnrolledMac: Codable, Hashable, Identifiable {
    let mac: String
    let host: String

    var id: String { mac }
}

struct Route: Identifiable, Equatable {
    let mac: EnrolledMac
    let requestID: String
    let base: URL

    var id: String { requestID }
}

@MainActor
@Observable
final class ApproverModel {
    static let shared = ApproverModel()
    static let macsKey = "enrolled-macs"

    var macs: [EnrolledMac]
    var pushToken: String?
    var route: Route?
    var notice: String?

    init() {
        macs = UserDefaults.standard.data(forKey: Self.macsKey)
            .flatMap { try? JSONDecoder().decode([EnrolledMac].self, from: $0) } ?? []
    }

    func enrolled(_ mac: EnrolledMac) throws {
        macs = macs.filter { $0.mac != mac.mac } + [mac]
        try UserDefaults.standard.set(JSONEncoder().encode(macs), forKey: Self.macsKey)
    }

    /// A push is only a hint: the request is fetched from the enrolled Mac it
    /// names, over HTTPS to that Mac's own tailnet name, never a host the push picks.
    func open(mac name: String, id: String, url: String) {
        guard let mac = macs.first(where: { $0.mac == name }) else {
            notice = "A push named \(name), which this phone never enrolled with."
            return
        }
        guard let base = URL(string: url), base.scheme == "https", base.host() == mac.host else {
            notice = "A push for \(name) pointed somewhere other than \(mac.host)."
            return
        }
        route = Route(mac: mac, requestID: id, base: base)
    }
}
