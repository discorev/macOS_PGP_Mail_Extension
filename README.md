# GPGMail Extension
A Mail extension that uses Apple's MailKit API to sign, encrypt, decrypt and verify PGP mail (PGP/MIME and inline) with your GPG Suite keyring.

This project isn't part of, or endorsed by, GPGTools, and doesn't use the source code of their GPGMail plugin.

## Requirements
- macOS 15 or later
- [GPG Suite](https://gpgtools.org), which provides gpg, your keyring in `~/.gnupg` and `/Library/Frameworks/Libmacgpg.framework`
- Xcode 27 to build

## Build and enable
1. Open `GPGMail.xcodeproj`, choose the `GPGMail` scheme and build. Signing uses your own development team.
2. Run `GPGMail.app` once so macOS registers the extension it contains.
3. In Mail, go to Settings › Extensions and turn on GPGMailExtention.

Run the unit tests with:

```sh
xcodebuild test -project GPGMail.xcodeproj -scheme GPGMail -destination 'platform=macOS' -only-testing:GPGCoreTests
```

## Layout
- `GPGCore/`: a framework that imports only Foundation, so it can be reused on other platforms. It parses and writes MIME, recognises and decodes PGP/MIME and inline PGP, builds RFC 3156 signed and encrypted messages, parses gpg status lines and chooses keys. It reaches crypto only through the `PGPBackend` protocol, and works in CRLF line endings throughout.
- `GPGMailExtention/`: the MailKit extension. `LibmacgpgBackend` implements `PGPBackend` with Libmacgpg, and `MessageSecurityHandler` maps between Mail's types and GPGCore.
- `GPGCoreTests/`: unit tests. They replay recorded gpg runs from `Fixtures/` through a fake backend and never call gpg.
- `GPGMail/`: the host app that ships the extension.
