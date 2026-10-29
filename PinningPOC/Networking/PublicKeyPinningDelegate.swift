import CryptoKit
import Foundation
import os

/// Pinning by key: the server's public key itself must be in `Pinning.publicKeys`.
/// Same flow and same security as `PinningDelegate`; it just compares the key instead of its hash.
final class PublicKeyPinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
        async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.host == Pinning.host,
              let trust = challenge.protectionSpace.serverTrust
        else { return (.performDefaultHandling, nil) } // not our host: iOS decides

        // 1. Normal certificate check (trusted CA, hostname, dates). Always runs.
        guard SecTrustEvaluateWithError(trust, nil) else { return (.cancelAuthenticationChallenge, nil) }

        // 2. Key check: the server's public key must be one of our keys.
        if Pinning.isEnabled, !Pinning.publicKeys.contains(publicKey(trust) ?? "") {
            Logger().error("pinning_failure domain=\(Pinning.host, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil) // handshake stops: nothing is sent
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Base64(public key) of the server's certificate: the same text as between BEGIN/END PUBLIC KEY in openssl.
    private func publicKey(_ trust: SecTrust) -> String? {
        guard let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              let key = SecCertificateCopyKey(certificate),
              let rawKey = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              // iOS returns the bare key; CryptoKit adds the "EC P-256 key" header to get the standard format.
              let publicKey = try? P256.Signing.PublicKey(x963Representation: rawKey).derRepresentation
        else { return nil }
        return publicKey.base64EncodedString()
    }
}
