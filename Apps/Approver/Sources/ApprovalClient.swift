import CCSudoPhone
import Foundation

/// Fetches one parked request from the Mac that asked and posts the answer,
/// over HTTPS to that Mac's tailnet name; synckitd hands the request only to
/// the tailnet node it recorded for this phone at enrollment.
struct ApprovalClient {
    enum ClientError: Error, LocalizedError {
        case status(Int)
        case expired

        var errorDescription: String? {
            switch self {
            case let .status(code): "The Mac answered HTTP \(code)."
            case .expired: "This request expired or was already answered."
            }
        }
    }

    let route: Route

    var url: URL {
        route.base.appending(path: PendingApproval.path(id: route.requestID))
    }

    func fetch() async throws -> PendingApproval {
        let (data, response) = try await URLSession.shared.data(from: url)
        try check(response)
        return try JSONDecoder().decode(PendingApproval.self, from: data)
    }

    func post(_ answer: ApprovalAnswer) async throws {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(answer)
        let (_, response) = try await URLSession.shared.data(for: request)
        try check(response)
    }

    private func check(_ response: URLResponse) throws {
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        switch code {
        case 200 ..< 300: return
        case 404, 410: throw ClientError.expired
        default: throw ClientError.status(code)
        }
    }
}
