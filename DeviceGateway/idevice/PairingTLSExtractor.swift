//
//  PairingTLSExtractor.swift
//  Extract SecIdentity from iOS pairing file for TLS client auth
//

import Foundation
import Security

internal enum PairingTLSError: Error, CustomStringConvertible {
    case missingField(String)
    case invalidCertificate
    case invalidKey(String)
    case keychainError(OSStatus, String)

    var description: String {
        switch self {
        case .missingField(let f): return "Missing field: \(f)"
        case .invalidCertificate: return "Invalid certificate"
        case .invalidKey(let msg): return "Invalid key: \(msg)"
        case .keychainError(let code, let msg): return "Keychain \(code): \(msg)"
        }
    }
}

internal enum PairingTLSExtractor {

    static func extractIdentity(from pairingFileData: Data) throws -> SecIdentity {
        let plist = try PropertyListSerialization.propertyList(from: pairingFileData, options: [], format: nil)
        guard let dict = plist as? [String: Any] else {
            throw PairingTLSError.missingField("root dictionary")
        }
        guard let hostCertData = dict["HostCertificate"] as? Data else {
            throw PairingTLSError.missingField("HostCertificate")
        }
        guard let hostKeyData = dict["HostPrivateKey"] as? Data else {
            throw PairingTLSError.missingField("HostPrivateKey")
        }
        guard let cert = SecCertificateCreateWithData(nil, hostCertData as CFData) else {
            throw PairingTLSError.invalidCertificate
        }
        let key = try createRSAKey(from: hostKeyData)

        let tag = "minimuxer.debug.tls".data(using: .utf8)!

        // Clean old items with same tag (idempotent)
        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ] as CFDictionary)
        SecItemDelete([
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tag,
        ] as CFDictionary)

        // Add private key with tag
        let addKeyStatus = SecItemAdd([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: key,
        ] as CFDictionary, nil)
        guard addKeyStatus == errSecSuccess else {
            throw PairingTLSError.keychainError(addKeyStatus, "add RSA key")
        }

        // Add certificate with same tag — iOS links cert+key with same tag into identity
        let addCertStatus = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: cert,
        ] as CFDictionary, nil)
        guard addCertStatus == errSecSuccess else {
            throw PairingTLSError.keychainError(addCertStatus, "add cert")
        }

        // Query identity by applicationTag
        var idResult: CFTypeRef? = nil
        let idStatus = SecItemCopyMatching([
            kSecClass as String: kSecClassIdentity,
            kSecAttrApplicationTag as String: tag,
            kSecReturnRef as String: true,
        ] as CFDictionary, &idResult)
        guard idStatus == errSecSuccess, let cfId = idResult else {
            throw PairingTLSError.keychainError(idStatus, "identity lookup by tag")
        }
        return (cfId as! SecIdentity)
    }

    private static func createRSAKey(from pkcs1Data: Data) throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        if let k = SecKeyCreateWithData(pkcs1Data as CFData, attrs as CFDictionary, nil) {
            return k
        }
        let wrapped = wrapPKCS1InPKCS8(pkcs1Data)
        if let k = SecKeyCreateWithData(wrapped as CFData, attrs as CFDictionary, nil) {
            return k
        }
        throw PairingTLSError.invalidKey("not PKCS#1 nor PKCS#8")
    }

    private static func wrapPKCS1InPKCS8(_ pkcs1: Data) -> Data {
        var out = Data()
        let totalLen = UInt16(4 + 2 + 13 + 4 + pkcs1.count + 4)
        out.append(contentsOf: [0x30, 0x82])
        out.append(UInt8((totalLen >> 8) & 0xff))
        out.append(UInt8(totalLen & 0xff))
        out.append(contentsOf: [0x02, 0x01, 0x00])
        out.append(contentsOf: [0x30, 0x0d])
        out.append(contentsOf: [0x06, 0x09])
        out.append(contentsOf: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
        out.append(contentsOf: [0x05, 0x00])
        out.append(contentsOf: [0x04, 0x82])
        out.append(UInt8((pkcs1.count >> 8) & 0xff))
        out.append(UInt8(pkcs1.count & 0xff))
        out.append(pkcs1)
        return out
    }
}
