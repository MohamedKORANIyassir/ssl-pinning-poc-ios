import CryptoKit
import Foundation
import os

/// Pinning settings. Pins ship inside the app and change only with an app update.
enum Pinning {
    static let host = "api.github.com"

    /// Used by `PinningDelegate`: SHA-256 hash of the server's public key, Base64.
    static let pins: Set<String> = [
        "P5437A6f5e2OnunPOzNhRV2iWeOE1XGTN9xskQ53yTk=", // primary
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // backup (dummy)
    ]

    /// Used by `PublicKeyPinningDelegate`: the server's public key itself, Base64.
    static let publicKeys: Set<String> = [
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7TUu/xntlsqbuo3fCl5jpydyrTHZDZGQSllJri0v9y5MnKIAECGAWfjt4Nuv2JOnsqefiwtvazzP7U6o+uLLsw==", // primary
        "DUMMY_BACKUP_PUBLIC_KEY", // backup (dummy)
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

/// Pinning by hash: the SHA-256 of the server's public key must be in `Pinning.pins`.
/// iOS calls it during the TLS handshake, before any request data is sent.
final class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge)
        async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.host == Pinning.host,
              let trust = challenge.protectionSpace.serverTrust
        else { return (.performDefaultHandling, nil) } // not our host: iOS decides

        // 1. Normal certificate check (trusted CA, hostname, dates). Always runs.
        guard SecTrustEvaluateWithError(trust, nil) else { return (.cancelAuthenticationChallenge, nil) }

        // 2. Pin check: the hash of the server's public key must be one of our pins.
        if Pinning.isEnabled, !Pinning.pins.contains(publicKeyHash(trust) ?? "") {
            Logger().error("pinning_failure domain=\(Pinning.host, privacy: .public)")
            return (.cancelAuthenticationChallenge, nil) // handshake stops: nothing is sent
        }
        return (.useCredential, URLCredential(trust: trust))
    }

    /// Base64(SHA-256(public key)) of the server's certificate: the same value as the openssl pin command.
    private func publicKeyHash(_ trust: SecTrust) -> String? {
        guard let certificate = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first,
              let key = SecCertificateCopyKey(certificate),
              let rawKey = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              // iOS returns the bare key; CryptoKit adds the "EC P-256 key" header to get the standard format.
              let publicKey = try? P256.Signing.PublicKey(x963Representation: rawKey).derRepresentation
        else { return nil }
        return Data(SHA256.hash(data: publicKey)).base64EncodedString()
    }
}
