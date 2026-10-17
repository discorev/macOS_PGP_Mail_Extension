# Mail security fixtures

Run `./make-fixtures.sh` to regenerate the messages and GPG status/output records. The generator uses only the designated test key in the normal keyring; the stranger signing key is temporary and is removed with its isolated home.

| File | Shape | Expected decrypt/verify outcome | GPG exit |
|---|---|---|---:|
| `plain.eml` | Plain UTF-8 `text/plain` | No PGP; no GPG record | — |
| `inline-encrypted-known.eml` | Inline armored, signed + encrypted to known key | `GOODSIG` + `VALIDSIG`, `DECRYPTION_OKAY` | 0 |
| `inline-encrypted-unknown.eml` | Inline armored, stranger-signed + encrypted to known key | `ERRSIG` + `NO_PUBKEY`, `DECRYPTION_OKAY` | 2 |
| `pgpmime-encrypted-known.eml` | RFC 3156 encrypted `multipart/mixed` with base64 text and PDF parts | `GOODSIG` + `VALIDSIG`, `DECRYPTION_OKAY` | 0 |
| `pgpmime-encrypted-unknown.eml` | Same, stranger-signed | `ERRSIG` + `NO_PUBKEY`, `DECRYPTION_OKAY` | 2 |
| `pgpmime-signed.eml` | RFC 3156 detached `multipart/signed` | `GOODSIG` + `VALIDSIG` | 0 |
| `pgpmime-signed-bad.eml` | Same, signed body changed by one character | `BADSIG` | 1 |
| `inline-clearsigned.eml` | Inline clear-signed text | `GOODSIG` + `VALIDSIG` | 0 |

For each non-plain case, `.status` records GPG status-fd output and `.exit` records its process exit code. `.decrypted` contains plaintext output for encrypted cases and verified clear-signed output; detached-signature cases have no `.decrypted` file.
