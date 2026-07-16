import Foundation

/// One consent request: the exact argv that will run and the root-generated
/// nonce that kills replay. The origin identity is NOT here — the transport
/// stamps provenance server-side, and the verifier recomputes with the value
/// it trusts.
public struct ConsentRequest: Sendable {
    public let argv: [String]
    public let nonce: Data

    public init(argv: [String], nonce: Data) {
        self.argv = argv
        self.nonce = nonce
    }
}

/// Who produced a signature, which decides the enrolled key and the
/// origin_host the verifier recomputes with: `.local` verifies against
/// /etc/cc-sudo/trusted/self.pub with an empty origin_host; `.peer` against
/// /etc/cc-sudo/trusted/peers/<host>.pub with this host's own identity.
public enum SignatureOrigin: Sendable, Equatable {
    case local
    case peer(host: String)
}

/// A signature obtained through some consent transport. The transport is
/// UNTRUSTED: nothing here is believed until the root verifier recomputes the
/// subject and checks the signature against an enrolled public key.
public struct SignedConsent: Sendable {
    public let keyID: String
    public let signature: Data
    public let origin: SignatureOrigin

    public init(keyID: String, signature: Data, origin: SignatureOrigin) {
        self.keyID = keyID
        self.signature = signature
        self.origin = origin
    }
}

/// The four consent-transport failures. `denied` is TERMINAL — no strategy may
/// route past a human's rejection. `unavailable`/`screenLocked` mean this
/// transport cannot fire right now and the next strategy may try.
public enum ConsentError: Error, Sendable, Equatable {
    case denied
    case unavailable(String)
    case screenLocked(String)
    case malformedResponse(String)
}

/// A way to obtain an SE signature over nonce ‖ subject: the local helper
/// spawn or the synckitd socket. Both return opaque material for the verifier
/// to check — a source never decides anything.
public protocol ConsentSource: Sendable {
    func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent
}

/// Chains two sources with the engine's routing invariants: `unavailable` and
/// `screenLocked` fall through to the fallback; a denial is terminal and a
/// malformed response is fatal — neither ever routes onward.
public struct FallbackConsentSource: ConsentSource {
    let primary: any ConsentSource
    let fallback: any ConsentSource

    public init(primary: any ConsentSource, fallback: any ConsentSource) {
        self.primary = primary
        self.fallback = fallback
    }

    public func obtainSignature(_ request: ConsentRequest) async throws -> SignedConsent {
        do {
            return try await primary.obtainSignature(request)
        } catch let error as ConsentError {
            switch error {
            case .unavailable, .screenLocked:
                return try await fallback.obtainSignature(request)
            case .denied, .malformedResponse:
                throw error
            }
        }
    }
}
