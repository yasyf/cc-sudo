import AuthKit
import Foundation
import os

/// The local prompt path: the root verifier re-enters itself in the console
/// user's GUI session (`launchctl asuser <uid>`) as the hidden `prompt-helper`
/// shim, which drops to that user and spawns the PINNED authkit as its direct
/// same-user child (see `PrivilegedSpawn`). Routing the spawn through the
/// verifier — rather than `sudo -u` — makes the pinned cc-sudo binary authkit's
/// parent, so authkit's caller pin validates; the old `sudo -u` hop left a root
/// `sudo` monitor as the parent and failed that pin before any sheet appeared.
/// The helper receives the full argv and the nonce on stdin, hashes and
/// displays the argv ITSELF (display-digest binding), and returns
/// `{key_id, sig}` on stdout.
///
/// Exit codes follow the frozen helper contract: 0 approved · 1 denied ·
/// 2 unavailable · 3 screen-locked. 2 and 3 let the strategy fall back to the
/// synckitd socket; a denial is terminal. A shim-internal failure (the drop or
/// spawn itself) exits outside that contract and surfaces as a malformed
/// response, never a false denial.
public struct LocalHelper: ConsentSource {
    let consoleUser: ConsoleUser
    /// The root-owned verifier path re-entered as `prompt-helper`. Injectable
    /// for tests; production is the installed NOPASSWD verifier.
    let verifier: String
    let runner: any ProcessRunner

    public init(
        consoleUser: ConsoleUser,
        verifier: String = RunClient.verifierPath,
        runner: any ProcessRunner = LiveProcessRunner()
    ) {
        self.consoleUser = consoleUser
        self.verifier = verifier
        self.runner = runner
    }

    public func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent {
        let payload = try JSONEncoder().encode(
            ConsentSignRequest(nonce: request.nonce.base64EncodedString(), argv: request.argv)
        )
        let invocation = PrivilegedSpawn.launchctlInvocation(
            verifier: verifier,
            consoleUID: consoleUser.uid,
            authkitSubcommand: "consent-sign"
        )
        let result = try await runner.run(
            executable: invocation.executable,
            arguments: invocation.arguments,
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
