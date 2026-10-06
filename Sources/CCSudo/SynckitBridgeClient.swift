import Foundation

struct SynckitBridgeClient: SynckitConsentClient {
    static let sudo = "/usr/bin/sudo"

    let home: URL?
    let userID: uid_t?
    let runner: any ProcessRunner

    init(home: URL?, userID: uid_t?, runner: any ProcessRunner = LiveProcessRunner()) {
        self.home = home
        self.userID = userID
        self.runner = runner
    }

    func requestConsent(_ params: SynckitConsentParams) async throws -> SynckitConsentResult {
        guard let home, let userID else {
            throw SynckitClient.ClientError.unavailable("no invoking user")
        }
        let socketPath: String
        do {
            socketPath = try SynckitClient.socketPath(home: home)
        } catch {
            throw SynckitClient.ClientError.unavailable(String(describing: error))
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
