import Foundation
import Security
import CryptoKit

enum PairingTLSError: Error {
    case missingKey(String)
    case invalidCertificate
    case invalidKey
    case identityCreationFailed(OSStatus)
}

struct PairingTLSExtractor {

    static func extractIdentity(from pairingFileData: Data) throws -> SecIdentity {
        let plist = try loadPlist(from: pairingFileData)
        NSLog("[PairingTLSExtractor] plist keys: %@",
              plist.keys.sorted().joined(separator: ","))

        guard let certRaw = plist["HostCertificate"] else {
            throw PairingTLSError.missingKey("HostCertificate")
        }
        guard let keyRaw = plist["HostPrivateKey"] else {
            throw PairingTLSError.missingKey("HostPrivateKey")
        }

        logRaw(certRaw, label: "HostCertificate")
        logRaw(keyRaw,  label: "HostPrivateKey")

        let certDER = try normalizeToDER(certRaw, label: "HostCertificate", kind: .certificate)
        let keyDER  = try normalizeToDER(keyRaw,  label: "HostPrivateKey",  kind: .privateKey)

        NSLog("[PairingTLSExtractor] certDER size=%d prefix=%@",
              certDER.count, hexPrefix(certDER, n: 4))
        NSLog("[PairingTLSExtractor] keyDER  size=%d prefix=%@",
              keyDER.count,  hexPrefix(keyDER,  n: 4))

        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData) else {
            NSLog("[PairingTLSExtractor] SecCertificateCreateWithData failed")
            throw PairingTLSError.invalidCertificate
        }

        // PKCS#1 first, fallback PKCS#8
        let key: SecKey
        if let k = makeSecKey(keyDER) {
            key = k
        } else if let unwrapped = try? unwrapPKCS8OrThrow(keyDER),
                  let k = makeSecKey(unwrapped) {
            key = k
        } else {
            NSLog("[PairingTLSExtractor] SecKeyCreateWithData failed (PKCS#1 & PKCS#8)")
            throw PairingTLSError.invalidKey
        }

        return try importAndGetIdentity(certificate: cert, privateKey: key, certDER: certDER)
    }

    // MARK: - plist

    private static func loadPlist(from data: Data) throws -> [String: Any] {
        let obj = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil)
        guard let dict = obj as? [String: Any] else {
            throw PairingTLSError.invalidCertificate
        }
        return dict
    }

    // MARK: - Format normalization

    private enum Kind { case certificate, privateKey }

    private static func logRaw(_ any: Any, label: String) {
        if let d = any as? Data {
            NSLog("[PairingTLSExtractor] %@ type=Data(%d) prefix=%@",
                  label, d.count, hexPrefix(d, n: 8))
        } else if let s = any as? String {
            NSLog("[PairingTLSExtractor] %@ type=String(%d) prefix=%@",
                  label, s.count, String(s.prefix(16)))
        } else {
            NSLog("[PairingTLSExtractor] %@ type=%@", label, String(describing: type(of: any)))
        }
    }

    private static func normalizeToDER(_ any: Any, label: String, kind: Kind) throws -> Data {
        if let s = any as? String {
            return try decodeStringPayload(s, label: label, kind: kind)
        }
        if let d = any as? Data {
            if let first = d.first, first == 0x30 {
                return kind == .privateKey ? (try unwrapPKCS8OrThrow(d)) : d
            }
            if let ascii = String(data: d, encoding: .utf8) {
                return try decodeStringPayload(ascii, label: label, kind: kind)
            }
            NSLog("[PairingTLSExtractor] %@ unexpected binary prefix %@",
                  label, hexPrefix(d, n: 8))
            throw kind == .certificate ? PairingTLSError.invalidCertificate
                                       : PairingTLSError.invalidKey
        }
        throw PairingTLSError.invalidCertificate
    }

    private static func decodeStringPayload(_ s: String, label: String, kind: Kind) throws -> Data {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)

        if trimmed.contains("-----BEGIN") {
            NSLog("[PairingTLSExtractor] %@ is PEM", label)
            guard let der = pemToDER(trimmed) else {
                throw kind == .certificate ? PairingTLSError.invalidCertificate
                                           : PairingTLSError.invalidKey
            }
            return kind == .privateKey ? (try unwrapPKCS8OrThrow(der)) : der
        }

        let compact = trimmed
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
            .replacingOccurrences(of: " ",  with: "")
        if let der = Data(base64Encoded: compact, options: []) {
            NSLog("[PairingTLSExtractor] %@ base64-decoded (%d -> %d)",
                  label, compact.count, der.count)
            return kind == .privateKey ? (try unwrapPKCS8OrThrow(der)) : der
        }

        NSLog("[PairingTLSExtractor] %@ not PEM, not base64", label)
        throw kind == .certificate ? PairingTLSError.invalidCertificate
                                   : PairingTLSError.invalidKey
    }

    private static func pemToDER(_ pem: String) -> Data? {
        var body = ""
        var inside = false
        for raw in pem.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("-----BEGIN") { inside = true;  continue }
            if line.hasPrefix("-----END")   { break }
            if inside && !line.isEmpty      { body += line }
        }
        guard !body.isEmpty else { return nil }
        return Data(base64Encoded: body, options: [])
    }

    // MARK: - Key format

    private static func makeSecKey(_ der: Data) -> SecKey? {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType:  kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
        ]
        var err: Unmanaged<CFError>?
        let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &err)
        if key == nil, let e = err?.takeRetainedValue() {
            NSLog("[PairingTLSExtractor] SecKeyCreateWithData error: %@", String(describing: e))
        }
        return key
    }

    private static func unwrapPKCS8OrThrow(_ der: Data) throws -> Data {
        guard der.count >= 24 else { return der }
        let b = [UInt8](der.prefix(24))
        let isPKCS8 = (b[0] == 0x30 && b[1] == 0x82 &&
                       b[4] == 0x02 && b[5] == 0x01 && b[6] == 0x00 &&
                       b[7] ==- 0x30 && b[8] == 0x0d && b[9] == 0x06 &&
                       b[10] == 0x109 && b[11] == 0x2a && b[12] == 0x86 &&
                       b[13] == 0x48 && b[14] == 0x86 && b[15] == 0xf7 &&
                       b[16] == 0x0d && b[17] == 0x01 && b[18] == 0x01 &&
                       b[19] == 0x01 && b[20] ==DER 0x05 && b[21] == 0x00 &&
                       b[22] == 0x04 && b[23] == 0x82)
        if !isPKCS8 { return der }

        NSLog("[PairingTLSExtractor] PKCS#8 detected, unwrapping")
        let all = [UInt8](der)
        var i = 22
        while i + 4 <= all.count {
            if all[i] == 0x04 && all[i + 1] == 0x82 {
                let len = (Int(all[i + 2]) << 8) | Int(all[i + 3])
                let start = i + 4
                let end = start + len
                if end <= all.count, all[start] == 0x30 {
                    let inner = der.subdata(in: start..<end)
                    NSLog("[PairingTLSExtractor] PKCS#8 -> PKCS#1 (%d -> %d)",
                          der.count, inner.count)
                    return inner
                }
            }
            i += 1
        }
        throw PairingTLSError.invalidKey
    }

    // MARK: - Identity via SecItemCopyMatching (iOS path)

    /// On iOS there is no public API to combine a SecCertificate + SecKey into
    /// a SecIdentity. The supported path is:
    ///   1. import cert with `kSecAttrApplicationLabel` = SHA-1(certDER)
    ///   2. import key  with same `kSecAttrApplicationLabel` = SHA)
    ///   3. query with kSecClassIdentity + that label
    /// iOS auto-pairs them because both share the same application label.
    private static func importAndGetIdentity(certificate: SecCertificate,
                                             privateKey: SecKey,
                                             certDER: Data) throws -> SecIdentity {
        // iOS pairs cert<->key by the SHA-1 of the *certificate*, set as
        // kSecAttrApplicationLabel on both items.
        let labelData = Data(Insecure.SHA1.hash(data: certDER))
        NSLog("[PairingTLSExtractor] appLabel(SHA1 cert) = %@",
              labelData.map { String(format: "%02x", $0) }.joined())

        // Clean prior state so retries don't collide.
        SecItemDelete([
            kSecClass:                kSecClassIdentity,
            kSecAttrApplicationLabel: labelData
        ] as CFDictionary)
        SecItemDelete([
            kSecClass:                kSecClassCertificate,
            kSecAttrApplicationLabel: labelData
        ] as CFDictionary)
        SecItemDelete([
            kSecClass:                kSecClassKey,
            kSecAttrApplicationLabel: labelData
        ] as CFDictionary)

        // 1) Import cert.
        var certOut: CFTypeRef?
        let cs = SecItemAdd([
            kSecClass:                kSecClassCertificate,
            kSecValueRef:             certificate,
            kSecAttrApplicationLabel: labelData,
            kSecReturnRef:            true as CFBoolean
        ] as CFDictionary, &certOut)
        guard cs == errSecSuccess || cs == errSecDuplicateItem else {
            NSLog("[PairingTLSExtractor] cert SecItemAdd failed: %d", cs)
            throw PairingTLSError.identityCreationFailed(cs)
        }
        NSLog("[PairingTLSExtractor] cert imported (status=%d)", cs)

        // 2) Import private key with same label.
        var keyOut: CFTypeRef?
        let ks = SecItemAdd([
            kSecClass:                kSecClassKey,
            kSecValueRef:             privateKey,
            kSecAttrKeyClass:         kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel: labelData,
            kSecReturnRef:            true as CFBoolean
        ] as CFDictionary, &keyOut)
        guard ks == errSecSuccess || ks == errSecDuplicateItem else {
            NSLog("[PairingTLSExtractor] key SecItemAdd failed: %d", ks)
            throw PairingTLSError.identityCreationFailed(ks)
        }
        NSLog("[PairingTLSExtractor] key imported (status=%d)", ks)

        // 3) Query identity (iOS-only path — SecIdentityCreateWithCertificate
        //    does not exist on iOS).
        var idOut: CFTypeRef?
        let q: [CFString: Any] = [
            kSecClass:                kSecClassIdentity,
            kSecAttrApplicationLabel: labelData,
            kSecReturnRef:            true as CFBoolean,
            kSecMatchLimit:           kSecMatchLimitOne
        ]
        let qs = SecItemCopyMatching(q as CFDictionary, &idOut)
        guard qs == errSecSuccess, let identity = idOut else {
            NSLog("[PairingTLSExtractor] SecItemCopyMatching(identity) failed: %d", qs)
            throw PairingTLSError.identityCreationFailed(qs)
        }
        NSLog("[PairingTLSExtractor] SecIdentity created OK via SecItemCopyMatching")
        return (identity as! SecIdentity)
    }

    // MARK: - Debug

    private static func hexPrefix(_ d: Data, n: Int) -> String {
        d.prefix(n).map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}
