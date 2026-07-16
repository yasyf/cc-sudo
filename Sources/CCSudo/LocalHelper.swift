import AuthKit
import Foundation
import os

/// The local prompt path: root re-homes the PINNED authkit binary into the
/// console user's GUI session (`launchctl asuser <uid>`) and drops to that
/// user (`sudo -u`) so the helper reaches the user's Secure-Enclave key and
/// renders the Touch ID sheet on the console. The helper receives the full
/// argv and the nonce on stdin, hashes and displays the argv ITSELF
/// (display-digest binding), and returns `{key_id, sig}` on stdout.
///
/// Exit codes follow the frozen helper contract: 0 approved · 1 denied ·
/// 2 unavailable · 3 screen-locked. 2 and 3 let the strategy fall back to the
/// synckitd socket; a denial is terminal.
public struct LocalHelper: ConsentSource {
    static let launchctl = "/bin/launchctl"
    static let sudo = "/usr/bin/sudo"

    let helperBinary: URL
    let consoleUser: ConsoleUser
    let runner: any ProcessRunner

    /// `helperBinary` must be the path HelperTrust just validated — this type
    /// execs it verbatim and never re-resolves.
    public init(helperBinary: URL, consoleUser: ConsoleUser, runner: any ProcessRunner = LiveProcessRunner()) {
        self.helperBinary = helperBinary
        self.consoleUser = consoleUser
        self.runner = runner
    }

    public func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent {
        let payload = try JSONEncoder().encode(
            ConsentSignRequest(nonce: request.nonce.base64EncodedString(), argv: request.argv)
        )
        let result = try await runner.run(
            executable: Self.launchctl,
            arguments: [
                "asuser", String(consoleUser.uid),
                Self.sudo, "-u", "#\(consoleUser.uid)", "-H",
                helperBinary.path(), "consent-sign",
            ],
            stdin: payload,
            environment: nil
        )
        let stderr = result.stderr.utf8Lossy
        switch result.exitCode {
        case 0:
            guard let response = try? JSONDecoder().decode(ConsentSignResponse.self, from: result.stdout),
                  let signature = Data(base64Encoded: response.sig)
            else {
                throw ConsentError.malformedResponse("helper approved but emitted an unparseable response")
            }
            return SignedConsent(keyID: response.keyID, signature: signature, origin: .local)
        case 1:
            throw ConsentError.denied
        case 2:
            Logger.consent.info("local helper unavailable: \(stderr, privacy: .public)")
            throw ConsentError.unavailable(stderr)
        case 3:
            throw ConsentError.screenLocked(stderr)
        default:
            throw ConsentError.malformedResponse("helper exited \(result.exitCode): \(stderr)")
        }
    }
}
