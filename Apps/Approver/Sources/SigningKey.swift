import Foundation
import LocalAuthentication
import Security

/// The phone's two Secure Enclave P-256 keys. `approver` signs approvals and
/// is usable only after a Face ID match against the faces enrolled when it
/// was made; each signature evaluates a fresh LAContext, so one look signs
/// once. `transport` needs no biometry and only proves to synckitd that a
/// fetch or an answer comes from this phone.
enum SigningKey {
    enum KeyError: Error, LocalizedError {
        case security(String)
        case faceIDRequired

        var errorDescription: String? {
            switch self {
            case let .security(detail): detail
            case .faceIDRequired: "cc-sudo approves only with Face ID, and Face ID is not set up on this phone."
            }
        }
    }

    enum Role: String {
        case approver
        case transport

        var tag: Data { Data("com.yasyf.cc-sudo.approver.\(rawValue)".utf8) }

        var flags: SecAccessControlCreateFlags {
            switch self {
            case .approver: [.privateKeyUsage, .biometryCurrentSet]
            case .transport: [.privateKeyUsage]
            }
        }
    }

    static func requireFaceID(_ context: LAContext = LAContext()) throws {
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error),
              context.biometryType == .faceID
        else {
            throw KeyError.faceIDRequired
        }
    }

    static func publicKey(_ role: Role) throws -> Data {
        let key = try existing(role, context: nil) ?? create(role)
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw KeyError.security("the Secure Enclave key has no public half")
        }
        var error: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw KeyError.security(describe(error))
        }
        return bytes
    }

    static func approve(_ message: Data, reason: String) async throws -> Data {
        let context = LAContext()
        defer { context.invalidate() }
        try requireFaceID(context)
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        guard let key = try existing(.approver, context: context) else {
            throw KeyError.security("no approver key on this phone; enroll it at a Mac")
        }
        return try sign(message, with: key)
    }

    static func authenticate(_ message: Data) throws -> Data {
        guard let key = try existing(.transport, context: nil) else {
            throw KeyError.security("no transport key on this phone; enroll it at a Mac")
        }
        return try sign(message, with: key)
    }

    private static func sign(_ message: Data, with key: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data? else {
            throw KeyError.security(describe(error))
        }
        return signature
    }

    private static func existing(_ role: Role, context: LAContext?) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: role.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return (item as! SecKey)
        case errSecItemNotFound:
            return nil
        default:
            throw KeyError.security("keychain lookup failed: \(status)")
        }
    }

    private static func create(_ role: Role) throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            role.flags,
            &error
        ) else {
            throw KeyError.security(describe(error))
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: role.tag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeyError.security(describe(error))
        }
        return key
    }

    private static func describe(_ error: Unmanaged<CFError>?) -> String {
        error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown Security error"
    }
}
