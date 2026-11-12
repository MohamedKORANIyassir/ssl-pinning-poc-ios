# PinningPOC: SSL pinning demo (iOS)

Demo for the RFC "SSL Pinning for Yassir POS". One call: `GET https://api.github.com/users`.

## Files

- `Networking/Pinning.swift`: settings (host, pins, keys, on/off) and `PinningDelegate`, pinning by the **hash** of the key (used by default)
- `Networking/PublicKeyPinningDelegate.swift`: pinning by the **key itself**
- `Networking/APIClient.swift`: the call; `makeDelegate()` picks which delegate to use
- `App/PinningPOCApp.swift`: the screen

## How it works

During the TLS handshake iOS asks the pinning delegate (`PinningDelegate` or `PublicKeyPinningDelegate`) whether to trust the server:

1. Normal certificate check (trusted CA, hostname, dates).
2. Pin check: SHA-256 of the **root CA's** public key (the last certificate in the chain) must be one of our pins.

If either fails, the handshake is cancelled: **no request data is sent**, the app shows
"Secure connection failed. Check your network or update the app." and never retries without pinning.

## Root pinning, not leaf

The server's chain is `[server certificate (leaf), intermediate CA, root CA]`. This POC pins the **root CA**, the last one.

| | Leaf pinning | Root pinning (this POC) |
|---|---|---|
| What's pinned | The server's own key | The key of the CA at the top of the chain |
| When the server renews or changes its key | Pin breaks; needs an app update or the backup pin | Nothing changes (roots last 10-20+ years) |
| Blocks Proxyman, MDM/malware CAs, other CAs | Yes | Yes |
| A certificate from the **same** CA for our name, obtained by someone else | Blocked | Passes (needs control of our domain) |

GitHub's chain can end at either of two roots, so both are pinned: they also act as each other's backup.
The root isn't sent by the server; iOS adds it from the phone's trust store, which is why the pin check runs
**after** `SecTrustEvaluateWithError`.

## On / off

| Build | Pinning |
|---|---|
| Release | Always ON. Only the remote switch can turn it OFF (emergency). |
| Debug | OFF by default (so Proxyman works). Turn on "Debug opt-in". |

The remote switch can only turn pinning off. It never sends pins; pins change only with an app update.


## Two ways to pin the key

Two classes, one per way: `PinningDelegate` (Scenario A, hash, used by default) and `PublicKeyPinningDelegate` (Scenario B, the key itself).

Both start from the **same bytes**: the root CA's public key in the standard format (SPKI = "key type" header + key).
They only differ in whether we hash those bytes.

| | Scenario A: hash of the key (active) | Scenario B: the key itself |
|---|---|---|
| What's stored in the app | `sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=` | `MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEdvqZ…/usZzkOj` |
| Length | Always 44 characters | 160 (EC P-384) to ~730 (RSA 4096) characters |
| Security | Same | Same (a public key is public; the secret is the server's private key, which is never involved) |
| Same format as Android OkHttp / `cert-pins.sh` / RFC | ✅ | ❌ |
| Swift | `PinningDelegate`: `SHA256(spki).base64` | `PublicKeyPinningDelegate`: `spki.base64` |

**Recommendation:** Scenario A. Scenario B is useful to see and compare the actual key.

### Get the root's pin and key

Run in Terminal with Proxyman off. The server doesn't send the root, so the commands first find the root's
name in the server's chain, then take that root from the Mac's trust store.

Paste the **whole block at once, in one Terminal window**: steps 2a and 2b use `$ROOT` from the lines above
them, and it is empty in a new window.

```sh
H=api.github.com
# 1. The root's name: the last issuer (i:) in the chain the server sends
ROOT=$(openssl s_client -connect $H:443 -servername $H -showcerts </dev/null 2>/dev/null \
  | grep -E "^ *i:" | tail -1 | sed -E 's/.*CN ?= ?//')
echo "Root: [$ROOT]"   # must show a name; if empty, see below

# 2a. Pin (Scenario A): paste into Pinning.pins
security find-certificate -c "$ROOT" -p /System/Library/Keychains/SystemRootCertificates.keychain \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# 2b. Key (Scenario B): paste into Pinning.publicKeys
security find-certificate -c "$ROOT" -p /System/Library/Keychains/SystemRootCertificates.keychain \
  | openssl x509 -pubkey -noout \
  | grep -v "PUBLIC KEY" \
  | tr -d '\n'; echo
```

If `security` says *"The specified item could not be found in the keychain"*:

1. `Root:` is empty: the block wasn't run in one go. Paste it again, all at once.
2. `Root:` shows a name: print the chain to see the exact name, then put it in `ROOT` by hand:

   ```sh
   openssl s_client -connect $H:443 -servername $H -showcerts </dev/null 2>/dev/null | grep -E "^ *[0-9]+ s:|^ *i:"
   ROOT="USERTrust ECC Certification Authority"   # the last i: name from the output above
   ```

GitHub's roots today:

| Root | Key type | Valid until | Pin |
|---|---|---|---|
| Sectigo Public Server Authentication Root E46 | EC P-384 | 2046 | `sLVjNUaFYfW7n6EtgBeEpjOlcnBdNPMrZDRF36iwBdE=` |
| USERTrust ECC Certification Authority | EC P-384 | 2038 | `ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=` |

What each step does:

| Step | Pin | Key |
|---|---|---|
| `openssl s_client … -showcerts \| grep … \| sed …` | Finds the root's name (last issuer in the chain) | same |
| `security find-certificate -c "$ROOT" -p` | Gets the root certificate from the Mac's trust store | same |
| `openssl x509 -pubkey -noout` | Takes the public key out of the certificate (multi-line text with BEGIN/END) | same |
| `openssl pkey -pubin -outform der` | Turns it into raw bytes | — |
| `openssl dgst -sha256 -binary` | Hashes the bytes with SHA-256 | — |
| `openssl enc -base64` | Writes the hash as text (44 characters) | — |
| `grep -v "PUBLIC KEY"` | — | Removes the BEGIN/END lines |
| `tr -d '\n'; echo` | — | Joins the lines into one |

To pin the **leaf** instead (the server's own key), the same pipelines start with
`openssl s_client -connect $H:443 -servername $H </dev/null 2>/dev/null` instead of `security find-certificate …`,
and the code uses `.first` instead of `.last`.

### Working with the key vs working with the pin

Same security, same behavior in the app, same result when the server renews or rotates its key.
The difference is in day-to-day work:

| Task | Working with the **pin** (Scenario A) | Working with the **key** (Scenario B) |
|---|---|---|
| What you get from the server | A 44-character hash | The key itself: 124 characters (EC P-256), ~400 (RSA 2048), ~730 (RSA 4096) |
| What the app does on each handshake | Reads the key, hashes it, compares | Reads the key, compares (no hashing; the hash takes microseconds anyway) |
| Reading it | Opaque: you can't tell the key type or anything else from it | You can decode it (`openssl pkey -pubin -noout -text`) to see the key type, size and curve |
| Typing / pasting | Short, one line, easy to check by eye | Long; a missing or extra character, or a line break left in, breaks every request |
| Code review | One short line per pin; easy to diff | Long lines; hard to compare in a PR |
| Backup key from the backend team | They send the hash (or the key, and you hash it) | They send the public key |
| Sharing with Android | Same value works in OkHttp `CertificatePinner` (`sha256/…`) | Android can't use it directly; OkHttp only accepts hashes |
| Checking with `cert-pins.sh` / RFC docs | Same format | Needs converting first |
| When the server renews **with the same key** | Pin unchanged | Key unchanged |
| When the server **changes its key** | Need the new pin (app update, or switch to the backup) | Need the new key (same) |
| Is it secret? | No | No. Both are public; only the server's private key is secret, and it's never in the app |

**In short:** the pin is the key's short fingerprint. Use the **pin** in the code (shorter, standard, shared with Android).
Use the **key** when you want to look at what the server actually sends, for example to check the key type before choosing how to hash it.

Switch to Scenario B: in `APIClient.swift`, change `makeDelegate()` to return `PublicKeyPinningDelegate()`.

## Demo videos

Both videos run the same test with Proxyman intercepting `api.github.com`:
pinning blocks the request, and Proxyman shows "Possible Certificate Pinning" (it only sees the hostname).

### Pinning by pin (hash): `PinningDelegate`
https://github.com/user-attachments/assets/85128db9-8adf-4b5e-bccb-992aa1d42381



### Pinning by key: `PublicKeyPinningDelegate`
https://github.com/user-attachments/assets/bb6e98c7-0df6-47e8-881c-ccce7dfcc01e






