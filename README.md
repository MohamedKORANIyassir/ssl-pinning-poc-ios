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
2. Pin check: SHA-256 of the server's public key must be one of our 2 pins (primary + backup).

If either fails, the handshake is cancelled: **no request data is sent**, the app shows
"Secure connection failed. Check your network or update the app." and never retries without pinning.

## On / off

| Build | Pinning |
|---|---|
| Release | Always ON. Only the remote switch can turn it OFF (emergency). |
| Debug | OFF by default (so Proxyman works). Turn on "Debug opt-in". |

The remote switch can only turn pinning off. It never sends pins; pins change only with an app update.


## Two ways to pin the key

Two classes, one per way: `PinningDelegate` (Scenario A, hash, used by default) and `PublicKeyPinningDelegate` (Scenario B, the key itself).

Both start from the **same bytes**: the server's public key in the standard format (SPKI = "key type" header + key).
They only differ in whether we hash those bytes.

| | Scenario A: hash of the key (active) | Scenario B: the key itself |
|---|---|---|
| What's stored in the app | `P5437A6f5e2OnunPOzNhRV2iWeOE1XGTN9xskQ53yTk=` | `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7TUu…+uLLsw==` |
| Length | Always 44 characters | 124 (EC P-256) to ~730 (RSA 4096) characters |
| Security | Same | Same (a public key is public; the secret is the server's private key, which is never involved) |
| Same format as Android OkHttp / `cert-pins.sh` / RFC | ✅ | ❌ |
| Swift | `PinningDelegate`: `SHA256(spki).base64` | `PublicKeyPinningDelegate`: `spki.base64` |

**Recommendation:** Scenario A. Scenario B is useful to see and compare the actual key.

### Get the pin (Scenario A)

Run in Terminal with Proxyman off. Prints one line: paste it into `Pinning.pins`.

```sh
H=api.github.com
openssl s_client -connect $H:443 -servername $H </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Output today: `P5437A6f5e2OnunPOzNhRV2iWeOE1XGTN9xskQ53yTk=`

### Get the key (Scenario B)

Run in Terminal with Proxyman off. Prints one line: paste it into `Pinning.publicKeys`.

```sh
H=api.github.com
openssl s_client -connect $H:443 -servername $H </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | grep -v "PUBLIC KEY" \
  | tr -d '\n'; echo
```

Output today: `MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7TUu/xntlsqbuo3fCl5jpydyrTHZDZGQSllJri0v9y5MnKIAECGAWfjt4Nuv2JOnsqefiwtvazzP7U6o+uLLsw==`

What each step does:

| Step | Pin | Key |
|---|---|---|
| `openssl s_client …` | Connects to the server and gets its certificate | same |
| `openssl x509 -pubkey -noout` | Takes the public key out of the certificate (multi-line text with BEGIN/END) | same |
| `openssl pkey -pubin -outform der` | Turns it into raw bytes | — |
| `openssl dgst -sha256 -binary` | Hashes the bytes with SHA-256 | — |
| `openssl enc -base64` | Writes the hash as text (44 characters) | — |
| `grep -v "PUBLIC KEY"` | — | Removes the BEGIN/END lines |
| `tr -d '\n'; echo` | — | Joins the lines into one |

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

## Demo

1. Debug opt-in ON, tap GET /users: users load.
2. Proxyman with SSL Proxying on `api.github.com`: "Secure connection failed". Proxyman sees only the hostname.
3. Remote switch ON: works through Proxyman.
4. Everything off: works.
