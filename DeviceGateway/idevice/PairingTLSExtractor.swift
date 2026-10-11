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

        // Debug: log available keys and their types
        let keysList = dict.keys.sorted().joined(separator: ",")
        NSLog("[PairingTLSExtractor] plist keys: %@", keysList)

        let hostCertRaw = dict["HostCertificate"]
        NSLog("[PairingTLSExtractor] HostCertificate type: %@",
              hostCertRaw.map { String(describing: type(of: $0)) } ?? "nil")

        let hostCertData: Data
        if let d = hostCertRaw as? Data {
            hostCertData = d
        } else if let s = hostCertRaw as? String {
            if let d = Data(base64Encoded: s) {
                hostCertData = d
            } else {
                // Try PEM strip
                let stripped = s
                    .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
                    .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
                    .replacingOccurrences(of: "\n", with: "")
                    .replacingOccurrences(of: "\r", with: "")
                guard let d = Data(base64Encoded: stripped) else {
                    NSLog("[PairingTLSExtractor] cert string not base64/PEM")
                    throw PairingTLSError.invalidCertificate
                }
                hostCertData = d
            }
        } else {
            NSLog("[PairingTLSExtractor] unsupported HostCertificate type")
            throw PairingTLSError.invalidCertificate
        }

        NSLog("[PairingTLSExtractor] cert size: %d, prefix: %@",
              hostCertData.count,
              hostCertData.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " "))

        // If DER X.509 starts with 0x30 0x82, try direct
        guard let cert = SecCertificateCreateWithData(nil, hostCertData as CFData) else {
            NSLog("[PairingTLSExtractor] SecCertificateCreateWithData failed")
            throw PairingTLSError.invalidCertificate
        }

        let hostKeyRaw = dict["HostPrivateKey"]
        NSLog("[PairingTLSExtractor] HostPrivateKey type: %@",
              hostKeyRaw.map { String(describing: type(of: $0)) } ?? "nil")

        let hostKeyData: Data
        if let d = hostKeyRaw as? Data {
            hostKeyData = d
        } else if let s = hostKeyRaw as? String {
            if let d = Data(base64Encoded: s) {
                hostKeyData = d
            } else {
                throw PairingTLSError.invalidKey("string not base64")
            }
        } else {
            throw PairingTLSError.invalidKey("unsupported type")
        }

        NSLog("[PairingTLSExtractor] key size: %d, prefix: %@",
              hostKeyData.count,
              hostKeyData.prefix(8).map { String(format: "%02x", $0) }.joined(separator: " "))

        let key = try createRSAKey(from: hostKeyData)

        let tag = "minimuxer.debug.tls".data(using: .utf8)!

        SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ] as CFDictionary)
        SecItemDelete([
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tag,
        ] as CFDictionary)

        let addKeyStatus = SecItemAdd([
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: key,
        ] as CFDictionary, nil)
        guard addKeyStatus == errSecSuccess else {
            throw PairingTLSError.keychainError(addKeyStatus, "add RSA key")
        }

        let addCertStatus = SecItemAdd([
            kSecClass as String: kSecClassCertificate,
            kSecAttrApplicationTag as String: tag,
            kSecValueRef as String: cert,
        ] as CFDictionary, nil)
        guard addCertStatus == errSecSuccess else {
            throw PairingTLSError.keychainError(addCertStatus, "add cert")
        }

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
