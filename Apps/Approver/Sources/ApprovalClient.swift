import CCSudoPhone
import Foundation

/// Fetches one parked request from the Mac that asked and posts the answer,
/// over HTTPS to that Mac's tailnet name, each signed by the phone's transport
/// key; synckitd serves the request only to the tailnet node it recorded for
/// this phone and only under that key.
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
        let (data, response) = try await URLSession.shared.data(for: signed(method: "GET", body: Data()))
        try check(response)
        return try JSONDecoder().decode(PendingApproval.self, from: data)
    }

    func post(_ answer: ApprovalAnswer) async throws {
        var request = try signed(method: "POST", body: JSONEncoder().encode(answer))
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (_, response) = try await URLSession.shared.data(for: request)
        try check(response)
    }

    private func signed(method: String, body: Data) throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        if !body.isEmpty {
            request.httpBody = body
        }
        let signature = try SigningKey.authenticate(TransportAuth.message(method: method, id: route.requestID, body: body))
        request.setValue("\(TransportAuth.scheme) \(signature.base64EncodedString())", forHTTPHeaderField: "Authorization")
        return request
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
