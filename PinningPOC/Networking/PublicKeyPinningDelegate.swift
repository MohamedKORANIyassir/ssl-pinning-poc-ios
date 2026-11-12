import CryptoKit
import Foundation
import os

/// Pinning by key: the root CA's public key itself must be in `Pinning.publicKeys`.
/// Same flow and same security as `PinningDelegate`; it just compares the key instead of its hash.
final class PublicKeyPinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
        async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.host == Pinning.host,
              let trust = challenge.protectionSpace.serverTrust
        else { return (.performDefaultHandling, nil) } // not our host: iOS decides

        // 1. Normal certificate check (trusted CA, hostname, dates). Always runs.
        guard SecTrustEvaluateWithError(trust, nil) else { return (.cancelAuthenticationChallenge, nil) }

        // 2. Key check: the root CA's public key must be one of our keys.
        if Pinning.isEnabled, !Pinning.publicKeys.contains(publicKey(trust) ?? "") {
            Logger().error("pinning_failure domain=\(Pinning.host, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil) // handshake stops: nothing is sent
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Base64(public key) of the root CA certificate: the same text as between BEGIN/END PUBLIC KEY in openssl.
    /// Supports EC P-256 and P-384 keys (GitHub's roots are P-384). For any other key type (e.g. RSA) it returns nil,
    /// so every request is rejected: add support for the backend's key type before using it there.
    private func publicKey(_ trust: SecTrust) -> String? {
        // The chain iOS verified is [server certificate, intermediate CA, root CA]; `.last` is the root.
        // The root comes from the phone's trust store, so this must run after SecTrustEvaluateWithError.
        guard let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.last,
              let key = SecCertificateCopyKey(certificate),
              let rawKey = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              // iOS returns the bare key; CryptoKit adds the "EC key + curve" header to get the standard format.
              let publicKey = (try? P256.Signing.PublicKey(x963Representation: rawKey).derRepresentation)
                           ?? (try? P384.Signing.PublicKey(x963Representation: rawKey).derRepresentation)
        else { return nil }
        return publicKey.base64EncodedString()
    }
}
