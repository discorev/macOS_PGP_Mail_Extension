#!/bin/bash
set -euo pipefail

GPG=/usr/local/MacGPG2/bin/gpg
KNOWN=17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2
OUT="$(cd "$(dirname "$0")" && pwd)"
rm -f "$OUT/pgpmime-signed.decrypted" "$OUT/pgpmime-signed-bad.decrypted"
WORK="$(mktemp -d "/tmp/gpgmail-fixtures.XXXXXX")"
STRANGER_HOME="$WORK/stranger-home"
mkdir -m 700 "$STRANGER_HOME"
trap '"/usr/local/MacGPG2/bin/gpgconf" --homedir "$STRANGER_HOME" --kill all >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

# Only export the designated fixture public key from the normal keyring.
"$GPG" --batch --no-auto-key-retrieve --export "$KNOWN" > "$WORK/known.pub"
test -s "$WORK/known.pub"
"$GPG" --homedir "$STRANGER_HOME" --batch --no-auto-key-retrieve --import "$WORK/known.pub" >/dev/null
"$GPG" --homedir "$STRANGER_HOME" --batch --no-auto-key-retrieve --pinentry-mode loopback \
  --passphrase '' --quick-generate-key 'GPGMail Fixture Stranger <stranger@example.invalid>' ed25519 sign 0 >/dev/null
"$GPG" --homedir "$STRANGER_HOME" --with-colons --list-secret-keys 'stranger@example.invalid' > "$WORK/stranger.sec"
STRANGER="$(awk -F: '$1=="fpr"{print $10; exit}' "$WORK/stranger.sec")"
test -n "$STRANGER"

# Normalize LF-generated material when embedding it in RFC 5322/MIME files.
crlf() { perl -0777 -pe 's/\r?\n/\r\n/g' "$1"; }
mail_headers() {
  local stem="$1" subject="$2"
  printf 'From: GPGMail Test <ollie@ollies.email>\r\nTo: GPGMail Test <ollie@ollies.email>\r\nDate: Fri, 16 Oct 2026 12:00:00 +0000\r\nMessage-ID: <fixture-%s@gpgmail.test>\r\nSubject: %s\r\n' "$stem" "$subject"
}
armor_encrypt_sign() {
  local plaintext="$1" signer="$2" homedir="${3:-}"
  if [[ -n "$homedir" ]]; then
    "$GPG" --homedir "$homedir" --batch --yes --no-auto-key-retrieve --trust-model always \
      --pinentry-mode loopback --passphrase '' --armor --local-user "$signer" --recipient "$KNOWN" \
      --sign --encrypt --output "$WORK/cipher.asc" "$plaintext" >/dev/null 2>&1
  else
    "$GPG" --batch --yes --no-auto-key-retrieve --trust-model always --pinentry-mode loopback \
      --passphrase '' --armor --local-user "$signer" --recipient "$KNOWN" --sign --encrypt \
      --output "$WORK/cipher.asc" "$plaintext" >/dev/null 2>&1
  fi
}
write_inline() {
  local stem="$1" signer="$2" plaintext="$3" homedir="${4:-}" rc=0
  armor_encrypt_sign "$plaintext" "$signer" "$homedir"
  {
    mail_headers "$stem" "$stem"
    printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Disposition: inline\r\n\r\n'
    crlf "$WORK/cipher.asc"
  } > "$OUT/$stem.eml"
  "$GPG" --batch --no-auto-key-retrieve --status-fd=3 --decrypt "$WORK/cipher.asc" \
    > "$OUT/$stem.decrypted" 3> "$OUT/$stem.status" || rc=$?
  printf '%s\n' "${rc:-0}" > "$OUT/$stem.exit"
}
write_encrypted_mime() {
  local stem="$1" signer="$2" homedir="${3:-}" rc=0
  armor_encrypt_sign "$WORK/mime-entity" "$signer" "$homedir"
  {
    mail_headers "$stem" "$stem"
    printf 'MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=CUT-HERE-1234567890\r\n\r\n'
    printf '%s\r\n' '--CUT-HERE-1234567890'
    printf 'Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n'
    printf '%s\r\n' '--CUT-HERE-1234567890'
    printf 'Content-Type: application/octet-stream\r\nContent-Disposition: inline; filename="encrypted.asc"\r\n\r\n'
    crlf "$WORK/cipher.asc"
    printf '%s--\r\n' '--CUT-HERE-1234567890'
  } > "$OUT/$stem.eml"
  "$GPG" --batch --no-auto-key-retrieve --status-fd=3 --decrypt "$WORK/cipher.asc" \
    > "$OUT/$stem.decrypted" 3> "$OUT/$stem.status" || rc=$?
  printf '%s\n' "${rc:-0}" > "$OUT/$stem.exit"
}

# Build a small structurally valid one-page PDF with computed xref offsets.
python3 -I - "$WORK/invoice.pdf" <<'PY'
import sys
from pathlib import Path
objects = [
    b'<< /Type /Catalog /Pages 2 0 R >>',
    b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
]
stream = b'BT /F1 12 Tf 20 50 Td (GPGMail test invoice 1042) Tj ET'
objects.append(b'<< /Length ' + str(len(stream)).encode() + b' >>\nstream\n' + stream + b'\nendstream')
pdf = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
offsets = [0]
for i, obj in enumerate(objects, 1):
    offsets.append(len(pdf))
    pdf.extend(f'{i} 0 obj\n'.encode() + obj + b'\nendobj\n')
xref = len(pdf)
pdf.extend(f'xref\n0 {len(offsets)}\n'.encode())
pdf.extend(b'0000000000 65535 f \n')
for offset in offsets[1:]:
    pdf.extend(f'{offset:010d} 00000 n \n'.encode())
pdf.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode())
Path(sys.argv[1]).write_bytes(pdf)
PY

# Ordinary baseline.
{
  mail_headers plain plain
  printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nCafé, naïve, £5 — ✓\r\nA plain fixture message.\r\n'
} > "$OUT/plain.eml"

# Inline encrypted plaintext intentionally uses LF-only lines and no MIME headers.
printf 'ISP support reference 1042\nCafé, naïve, £5 — ✓\nYour encrypted message is ready.\n' > "$WORK/inline-plaintext"
write_inline inline-encrypted-known "$KNOWN" "$WORK/inline-plaintext"
write_inline inline-encrypted-unknown "$STRANGER" "$WORK/inline-plaintext" "$STRANGER_HOME"

# Encrypted RFC 3156 payload: a multipart/mixed entity with base64 parts.
TEXT_B64="$(printf 'Café, naïve, £5 — ✓\nYour invoice is attached.\n' | base64 | tr -d '\n')"
PDF_B64="$(base64 < "$WORK/invoice.pdf" | tr -d '\n' | fold -w 76)"
{
  printf 'Content-Type: multipart/mixed; boundary="INNER-MIXED-98765"\r\nMIME-Version: 1.0\r\n\r\n'
  printf '%s\r\n' '--INNER-MIXED-98765'
  printf 'Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: inline\r\n\r\n%s\r\n' "$TEXT_B64"
  printf '%s\r\n' '--INNER-MIXED-98765'
  printf 'Content-Type: application/pdf\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment;filename="invoice.pdf"\r\n\r\n%s\r\n' "$PDF_B64"
  printf '%s--\r\n' '--INNER-MIXED-98765'
} > "$WORK/mime-entity"
write_encrypted_mime pgpmime-encrypted-known "$KNOWN"
write_encrypted_mime pgpmime-encrypted-unknown "$STRANGER" "$STRANGER_HOME"

# RFC 3156 signed entity is canonical CRLF data, including its final CRLF.
{
  printf 'Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n'
  printf 'Signed invoice notice 1042.\r\nCafé, naïve, £5 — ✓\r\n'
} > "$WORK/signed-part"
"$GPG" --batch --yes --no-auto-key-retrieve --pinentry-mode loopback --passphrase '' \
  --local-user "$KNOWN" --armor --digest-algo SHA256 --detach-sign --output "$WORK/signature.asc" \
  "$WORK/signed-part" >/dev/null 2>&1
make_signed_eml() {
  local stem="$1" part="$2"
  {
    mail_headers "$stem" "$stem"
    printf 'MIME-Version: 1.0\r\nContent-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="SIGNED-PART-123456"\r\n\r\n'
    printf '%s\r\n' '--SIGNED-PART-123456'
    cat "$part"
    printf '%s\r\n' '--SIGNED-PART-123456'
    printf 'Content-Type: application/pgp-signature; name="signature.asc"\r\nContent-Description: OpenPGP digital signature\r\nContent-Disposition: attachment; filename="signature.asc"\r\n\r\n'
    crlf "$WORK/signature.asc"
    printf '%s--\r\n' '--SIGNED-PART-123456'
  } > "$OUT/$stem.eml"
}
make_signed_eml pgpmime-signed "$WORK/signed-part"
cp "$WORK/signed-part" "$WORK/signed-part-bad"
perl -0777 -i -pe 's/notice 1042/notice 1043/' "$WORK/signed-part-bad"
make_signed_eml pgpmime-signed-bad "$WORK/signed-part-bad"

# Detached verification uses the exact first-part bytes extracted before the boundary.
for stem in pgpmime-signed pgpmime-signed-bad; do
  rc=0
  if [[ "$stem" == pgpmime-signed ]]; then part="$WORK/signed-part"; else part="$WORK/signed-part-bad"; fi
  "$GPG" --batch --no-auto-key-retrieve --status-fd=3 --verify "$WORK/signature.asc" "$part" \
    > "$OUT/$stem.decrypted" 3> "$OUT/$stem.status" || rc=$?
  printf '%s\n' "${rc:-0}" > "$OUT/$stem.exit"
  unset rc
done

# Clear-signed text fixture; --verify supplies the recorded status/exit, while --decrypt emits plaintext.
printf 'Clear-signed notice 1042.\nCafé, naïve, £5 — ✓\n' > "$WORK/clearsigned-plaintext"
"$GPG" --batch --yes --no-auto-key-retrieve --pinentry-mode loopback --passphrase '' \
  --local-user "$KNOWN" --armor --clearsign --output "$WORK/clearsigned.asc" \
  "$WORK/clearsigned-plaintext" >/dev/null 2>&1
{
  mail_headers inline-clearsigned inline-clearsigned
  printf 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Disposition: inline\r\n\r\n'
  crlf "$WORK/clearsigned.asc"
} > "$OUT/inline-clearsigned.eml"
"$GPG" --batch --no-auto-key-retrieve --status-fd=3 --verify "$WORK/clearsigned.asc" \
  > /dev/null 3> "$OUT/inline-clearsigned.status" || rc=$?
printf '%s\n' "${rc:-0}" > "$OUT/inline-clearsigned.exit"
"$GPG" --batch --no-auto-key-retrieve --decrypt "$WORK/clearsigned.asc" \
  > "$OUT/inline-clearsigned.decrypted" 2>/dev/null || true

printf 'Generated fixtures in %s\n' "$OUT"
