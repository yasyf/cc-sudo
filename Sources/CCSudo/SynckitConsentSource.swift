import AuthKit
import Foundation
import os

/// The routed/locked-Mac prompt path: consent.request over the console user's
/// synckitd socket. synckitd is TRANSPORT, never trust — it forwards
/// argv + nonce to a helper (local or a live peer's) opaquely and returns the
/// signature opaquely; the root verifier recomputes and checks everything.
///
/// `ttl_ms` is pinned to 0 so every call prompts, and `local_only` stays false
/// so a locked Mac routes to a live peer.
public struct SynckitConsentSource: ConsentSource {
    static let clientName = "cc-sudo"

    let client: any SynckitConsentClient
    /// The mesh name synckitd advertises for THIS host (engine `Self`); a
    /// local, non-routed approval comes back signed_by that name and verifies
    /// against the self key.
    let selfIdentity: String

    public init(client: any SynckitConsentClient, selfIdentity: String) {
        self.client = client
        self.selfIdentity = selfIdentity
    }

    public func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent {
        let params = SynckitConsentParams(
            client: Self.clientName,
            reason: Subject.display(argv: request.argv),
            subject: "sha256:" + Subject.argvDigestHex(argv: request.argv),
            argv: request.argv,
            nonce: request.nonce.base64EncodedString(),
            ttlMS: 0,
            localOnly: false
        )
        let result: SynckitConsentResult
        do {
            result = try await client.requestConsent(params)
        } catch let error as SynckitClient.ClientError {
            // A dead or absent daemon is an unavailable transport (fail closed
            // upstream); a live daemon answering an RPC error is fatal — the
            // engine contract says a fatal local prompt never routes.
            switch error {
            case .unavailable, .deadlineExceeded:
                throw ConsentError.unavailable(String(describing: error))
            case .rpc, .protocolViolation:
                throw ConsentError.malformedResponse(String(describing: error))
            }
        }

        switch result.verdict {
        case "approved":
            guard let attestation = result.attestation,
                  let signature = Data(base64Encoded: attestation.sig)
            else {
                // An approval without a checkable signature is worthless by
                // design — never accept a bare verdict.
                throw ConsentError.malformedResponse("approved verdict carried no attestation")
            }
            let origin: SignatureOrigin = attestation.signedBy == selfIdentity
                ? .local
                : .peer(host: attestation.signedBy)
            let routed = result.routed ?? false
            Logger.synckit.info(
                "approved by \(attestation.signedBy, privacy: .public) routed=\(routed, privacy: .public)"
            )
            return SignedConsent(keyID: attestation.keyID, signature: signature, origin: origin)
        case "denied":
            throw ConsentError.denied
        case "unavailable":
            throw ConsentError.unavailable("no live approver on the mesh")
        default:
            throw ConsentError.malformedResponse("unknown verdict \(result.verdict)")
        }
    }
}
