import Foundation
import Security

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

        // Log raw payload types once, so we can see PEM vs DER vs base64 for BOTH fields.
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

        // Try PKCS#1 first (most common), then PKCS#8.
        if let key = makeSecKey(keyDER) {
            return try makeIdentity(certificate: cert, privateKey: key)
        }
        // If we got here with a PKCS#8-looking payload that failed unwrap, try PKCS#8 directly.
        if let pkcs8Unwrapped = try? unwrapPKCS8OrThrow(keyDER),
           let key = makeSecKey(pkcs8Unwrapped) {
            return try makeIdentity(certificate: cert, privateKey: key)
        }

        NSLog("[PairingTLSExtractor] SecKeyCreateWithData failed for both PKCS#1 and PKCS#8")
        throw PairingTLSError.invalidKey
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
            // Case 1: starts with 0x30 -> ASN.1 DER
            if let first = d.first, first == 0x30 {
                return kind == .privateKey ? (try unwrapPKCS8OrThrow(d)) : d
            }
            // Case 2: ASCII (PEM or base64)
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

        // Raw base64 (may contain whitespace/newlines)
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

    /// Strip any PEM armor (CERTIFICATE, RSA PRIVATE KEY, PRIVATE KEY, etc).
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

    /// PKCS#8 PrivateKeyInfo header:
    /// 30 82 LL LL 02 01 00 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 04 82
    private static func unwrapPKCS8OrThrow(_ der: Data) throws -> Data {
        guard der.count >= 24 else { return der }
        let b = [UInt8](der.prefix(24))
        let isPKCS8 = (b[0] == 0x30 && b[1] == 0x82 &&
                       b[4] == 0x02 && b[5] == 0x01 && b[6] == 0x00 &&
                       b[7] == 0x30 && b[8] == 0x0d && b[9] == 0x06 &&
                       b[10] == 0x09 && b[11] == 0x2a && b[12] == 0x86 &&
                       b[13] == 0x48 && b[14] == 0x86 && b[15] == 0xf7 &&
                       b[16] == 0x0d && b[17] == 0x01 && b[18] == 0x01 &&
                       b[19] == 0x01 && b[20] == 0x05 && b[21] == 0x00 &&
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

    // MARK: - SecIdentity construction

    /// No public API to pair a SecCertificate + SecKey into a SecIdentity.
    /// On iOS the working path is: import both into the app's default keychain,
    /// then SecIdentityCreateWithCertificate(nil, cert, &id) auto-matches them
    /// via the SHA-1 of the cert's SPKI (Security.framework sets this as the
    /// key's kSecAttrApplicationLabel on import).
    private static func makeIdentity(certificate: SecCertificate,
                                     privateKey: SecKey) throws -> SecIdentity {
        let certLabel = "minimuxer-host-cert"
        let keyLabel  = "minimuxer-host-key"

        // Clean any prior import so we don't collide across retries.
        SecItemDelete([
            kSecClass: kSecClassCertificate,
            kSecAttrLabel: certLabel
        ] as CFDictionary)
        SecItemDelete([
            kSecClass: kSecClassKey,
            kSecAttrApplicationLabel: keyLabel.data(using: .utf8)!
        ] as CFDictionary)

        // 1) Import cert (persistent ref so identity lookup can find it).
        var certOut: CFTypeRef?
        let cs = SecItemAdd([
            kSecClass:       kSecClassCertificate,
            kSecValueRef:    certificate,
            kSecAttrLabel:   certLabel,
            kSecReturnRef:   true as CFBoolean
        ] as CFDictionary, &certOut)
        guard cs == errSecSuccess, let certRef = certOut else {
            NSLog("[PairingTLSExtractor] cert import failed: %d", cs)
            throw PairingTLSError.identityCreationFailed(cs)
        }
        let storedCert = (certRef as! SecCertificate)

        // 2) Import private key. SecIdentityCreateWithCertificate matches by
        //    kSecAttrApplicationLabel = SHA-1 of the cert's subject public key.
        //    We must set that label ourselves because SecKeyCreateWithData
        //    doesn't tag the imported key.
        guard let spki = SecCertificateCopyKey(storedCert),
              let spkiData = SecKeyCopyExternalRepresentation(spki, nil) as Data? else {
            NSLog("[PairingTLSExtractor] cannot extract SPKI from cert")
            throw PairingTLSError.invalidCertificate
        }
        let appLabel = sha1(spkiData)

        var keyOut: CFTypeRef?
        let ks = SecItemAdd([
            kSecClass:                kSecClassKey,
            kSecValueRef:             privateKey,
            kSecAttrKeyClass:         kSecAttrKeyClassPrivate,
            kSecAttrApplicationLabel: appLabel,
            kSecReturnRef:            true as CFBoolean
        ] as CFDictionary, &keyOut)
        guard ks == errSecSuccess else {
            NSLog("[PairingTLSExtractor] key import failed: %d", ks)
            throw PairingTLSError.identityCreationFailed(ks)
        }

        // 3) Build identity.
        var idOut: SecIdentity?
        let is_ = SecIdentityCreateWithCertificate(nil, storedCert, &idOut)
        guard is_ == errSecSuccess, let identity = idOut else {
            NSLog("[PairingTLSExtractor] SecIdentityCreateWithCertificate failed: %d", is_)
            throw PairingTLSError.identityCreationFailed(is_)
        }
        NSLog("[PairingTLSExtractor] SecIdentity created OK")
        return identity
    }

    /// Minimal SHA-1 (avoids importing CryptoKit on older SDKs).
    private static func sha1(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: 20)
        data.withUnsafeBytes { buf in
            var ctx = CC_SHA1_CTX()
            CC_SHA1_Init(&ctx)
            CC_SHA1_Update(&ctx, buf.baseAddress, CC_LONG(data.count))
            CC_SHA1_Final(&digest, &ctx)
        }
        return Data(digest)
    }

    // MARK: - Debug

    private static func hexPrefix(_ d: Data, n: Int) -> String {
        d.prefix(n).map { String(format: "%02x", $0) }.joined(separator: " ")
    }
}
