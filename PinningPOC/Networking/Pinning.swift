import CryptoKit
import Foundation
import os

/// Pinning settings. Pins ship inside the app and change only with an app update.
enum Pinning {
    static let host = "api.github.com"

    /// Root pinning: we pin the root CA at the end of the server's chain, not the server's own (leaf) key.
    /// The root survives the server's renewals and key changes. GitHub's chain can end at either root below.

    /// Used by `PinningDelegate`: SHA-256 hash of the root CA's public key, Base64.
    static let pins: Set<String> = [
        "sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=", // Sectigo Public Server Authentication Root E46 (EC P-384, until 2046)
        "ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=", // USERTrust ECC Certification Authority (EC P-384, until 2038)
    ]

    /// Used by `PublicKeyPinningDelegate`: the root CA's public key itself, Base64.
    static let publicKeys: Set<String> = [
        // Sectigo Public Server Authentication Root E46
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEdvqZqW4g7fnXd+MHO6jbPV846KtVplZP1kjq7H8tqsOyxXnsmWF/EHnHAlr5BDf1NDUrd85/II9SowCJ7NWnom1b40uSk6CA9QGU3PBoBx7N7v4lUrUgQxwb/usZzkOj",
        // USERTrust ECC Certification Authority
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEGqxUWqn5aCPnetUkb1PGWthLq8bVttHmc3Gu3ZzWDGH926CJA7gFFOxXzu5dP+Ihs8731Ip54KODfi2X0GHE8ZncJZFjq38wo7Rw4sehM5zzvy5cU7Ffs30yf4o043l5",
    ]

    /// Release: always on, unless the remote switch turns it off. Debug: off unless opted in.
    static var isEnabled: Bool {
        isEnabled(remoteSwitchOff: UserDefaults.standard.bool(forKey: "remote_pinning_off"),
                  debugPinningOn: UserDefaults.standard.bool(forKey: "debug_pinning_on"))
    }

    static func isEnabled(remoteSwitchOff: Bool, debugPinningOn: Bool) -> Bool {
        if remoteSwitchOff { return false } // the remote switch always wins
        #if DEBUG
        return debugPinningOn
        #else
        return true
        #endif
    }
}

/// Pinning by hash: the SHA-256 of the root CA's public key must be in `Pinning.pins`.
/// iOS calls it during the TLS handshake, before any request data is sent.
final class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
        async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.host == Pinning.host,
              let trust = challenge.protectionSpace.serverTrust
        else { return (.performDefaultHandling, nil) } // not our host: iOS decides

        // 1. Normal certificate check (trusted CA, hostname, dates). Always runs.
        guard SecTrustEvaluateWithError(trust, nil) else { return (.cancelAuthenticationChallenge, nil) }

        // 2. Pin check: the hash of the root CA's public key must be one of our pins.
        if Pinning.isEnabled, !Pinning.pins.contains(publicKeyHash(trust) ?? "") {
            Logger().error("pinning_failure domain=\(Pinning.host, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil) // handshake stops: nothing is sent
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Base64(SHA-256(public key)) of the root CA certificate: the same value as the openssl root pin command.
    /// Supports EC P-256 and P-384 keys (GitHub's roots are P-384). For any other key type (e.g. RSA) it returns nil,
    /// so every request is rejected: add support for the backend's key type before using it there.
    private func publicKeyHash(_ trust: SecTrust) -> String? {
        // The chain iOS verified is [server certificate, intermediate CA, root CA]; `.last` is the root.
        // The root comes from the phone's trust store, so this must run after SecTrustEvaluateWithError.
        guard let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.last,
              let key = SecCertificateCopyKey(certificate),
              let rawKey = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              // iOS returns the bare key; CryptoKit adds the "EC key + curve" header to get the standard format.
              let publicKey = (try? P256.Signing.PublicKey(x963Representation: rawKey).derRepresentation)
                           ?? (try? P384.Signing.PublicKey(x963Representation: rawKey).derRepresentation)
        else { return nil }
        return Data(SHA256.hash(data: publicKey)).base64EncodedString()
    }
}
