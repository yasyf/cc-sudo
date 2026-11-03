import Foundation
import LocalAuthentication
import Security

/// The phone's approver key: P-256, made inside the Secure Enclave, usable
/// only after a Face ID match against the faces enrolled when it was made.
/// Each signature evaluates a fresh LAContext, so one look signs once.
enum SigningKey {
    enum KeyError: Error, LocalizedError {
        case security(String)

        var errorDescription: String? {
            switch self {
            case let .security(detail): detail
            }
        }
    }

    static let tag = Data("com.yasyf.cc-sudo.approver.signing".utf8)

    static func publicKey() throws -> Data {
        let key = try existing(context: nil) ?? create()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw KeyError.security("the Secure Enclave key has no public half")
        }
        var error: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw KeyError.security(describe(error))
        }
        return bytes
    }

    static func sign(_ message: Data, reason: String) async throws -> Data {
        let context = LAContext()
        defer { context.invalidate() }
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        guard let key = try existing(context: context) else {
            throw KeyError.security("no approver key on this phone; enroll it at a Mac")
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data? else {
            throw KeyError.security(describe(error))
        }
        return signature
    }

    private static func existing(context: LAContext?) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
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

    private static func create() throws -> SecKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
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
                kSecAttrApplicationTag as String: tag,
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
