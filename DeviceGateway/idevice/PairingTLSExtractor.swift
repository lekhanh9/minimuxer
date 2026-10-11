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

        // Import into keychain (temp tag), then build SecIdentity
        let tag = "minimuxer.debug.tls.\(UUID().uuidString)".data(using: .utf8)!
        var keyPersistentRef: CFTypeRef? = nil
        let keyAttrs: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: key,
            kSecReturnPersistentRef as String: true,
        ]
        let addKeyStatus = SecItemAdd(keyAttrs as CFDictionary, &keyPersistentRef)
        guard addKeyStatus == errSecSuccess || addKeyStatus == errSecDuplicateItem else {
            throw PairingTLSError.keychainError(addKeyStatus, "add RSA key")
        }

        var certRef: CFTypeRef? = nil
        let certAttrs: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: cert,
            kSecReturnRef as String: true,
        ]
        let addCertStatus = SecItemAdd(certAttrs as CFDictionary, &certRef)
        guard addCertStatus == errSecSuccess || addCertStatus == errSecDuplicateItem else {
            throw PairingTLSError.keychainError(addCertStatus, "add cert")
        }

        guard let certFromChain = certRef as! SecCertificate? else {
            throw PairingTLSError.keychainError(-1, "cert ref nil")
        }

        // iOS doesn't expose SecIdentityCreateWithCertificate (macOS-only public API).
        // Use SecItemCopyMatching with kSecClassIdentity + kSecMatchCertificateRef
        // to find the identity formed by the just-added cert + key.
        let idQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecMatchCertificateRef as String: certFromChain,
            kSecReturnRef as String: true,
        ]
        var idResult: CFTypeRef? = nil
        let idStatus = SecItemCopyMatching(idQuery as CFDictionary, &idResult)
        guard idStatus == errSecSuccess, let id = idResult as! SecIdentity? else {
            throw PairingTLSError.keychainError(idStatus, "SecItemCopyMatching identity lookup")
        }
        return id
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
