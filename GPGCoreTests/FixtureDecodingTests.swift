//
//  FixtureDecodingTests.swift
//  GPGCoreTests
//
//  Every fixture case, end to end through MessageDecoder with a backend replaying its recorded gpg run.
//

import Foundation
import Testing
@testable import GPGCore

struct FixtureDecodingTests {
    static let testKey = "17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2"
    static let strangerKeyID = "12F87CD7AE0B268B"

    private func decode(_ name: String) throws -> (DecodedMessage, FixtureBackend) {
        let backend = try FixtureBackend(fixture: name)
        let decoded = try #require(try MessageDecoder(backend: backend).decode(Fixture.data("\(name).eml")))
        return (decoded, backend)
    }

    @Test(arguments: zip(["plain"] + Fixture.cases, [nil, .inlineEncrypted, .inlineEncrypted, .pgpMimeEncrypted, .pgpMimeEncrypted, .pgpMimeSigned, .pgpMimeSigned, .inlineSigned] as [MessageDecoder.Kind?]))
    func recognisesEachShape(name: String, kind: MessageDecoder.Kind?) throws {
        #expect(MessageDecoder.kind(of: try Fixture.data("\(name).eml")) == kind)
    }

    @Test(arguments: Fixture.cases)
    func decodedMessagesAreCanonicalAndKeepTheirHeaders(name: String) throws {
        let (decoded, _) = try decode(name)
        #expect(!decoded.data.hasBareLineFeed)
        let message = Mime.Part(from: decoded.data)
        #expect(message.headers["From"] == "GPGMail Test <ollie@ollies.email>")
        #expect(message.headers["Subject"] == name)
        #expect(message.headers["Message-ID"] == "<fixture-\(name)@gpgmail.test>")
        #expect(message.headers.values(for: "Content-Type").count == 1)
        #expect(message.headers.values(for: "MIME-Version") == ["1.0"])
    }

    @Test func plainMessageIsLeftAlone() throws {
        let backend = FixtureBackend(run: GPGRun(output: Data(), statusText: "", errorOutput: Data(), exitCode: 0))
        #expect(try MessageDecoder(backend: backend).decode(Fixture.data("plain.eml")) == nil)
        #expect(backend.recordedCalls.isEmpty)
    }

    @Test func inlineEncryptedFromKnownKey() throws {
        let (decoded, backend) = try decode("inline-encrypted-known")
        #expect(decoded.isEncrypted)
        #expect(decoded.signingError == nil)

        let signature = try #require(decoded.signatures.first)
        #expect(decoded.signatures.count == 1)
        #expect(signature.status == .good)
        #expect(signature.signerName == "GPGMail Extension TEST KEY")
        #expect(signature.signerEmail == "ollie@ollies.email")
        #expect(signature.fingerprint == Self.testKey)
        #expect(signature.validity == .ultimate)
        #expect(signature.hashAlgorithm?.name == "SHA512")
        #expect(signature.publicKeyAlgorithm?.name == "EdDSA")

        // Only the armour goes to gpg
        guard case .decrypt(let input) = try #require(backend.recordedCalls.first) else {
            Issue.record("Expected a decrypt call")
            return
        }
        #expect(input.utf8String.hasPrefix("-----BEGIN PGP MESSAGE-----\r\n"))
        #expect(input.utf8String.hasSuffix("-----END PGP MESSAGE-----\r\n"))

        // Bare LF plaintext becomes a proper text/plain entity
        let message = Mime.Part(from: decoded.data)
        #expect(message.headers["Content-Type"] == "text/plain; charset=UTF-8")
        #expect(message.headers["Content-Transfer-Encoding"] == "8bit")
        #expect(message.headers["Content-Disposition"] == "inline")
        #expect(message.body.utf8String == "ISP support reference 1042\r\nCafé, naïve, £5 — ✓\r\nYour encrypted message is ready.\r\n")
    }

    @Test func inlineEncryptedFromUnknownKeyStillDecrypts() throws {
        // gpg exited 2 for this one: decrypted fine, signed by a key we don't have
        #expect(try Fixture.run("inline-encrypted-unknown").exitCode == 2)
        let (decoded, _) = try decode("inline-encrypted-unknown")
        #expect(decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.unknownKey(keyID: Self.strangerKeyID)])
        #expect(decoded.signingError == .invalidSignature(.unknownKey(keyID: Self.strangerKeyID)))
        #expect(Mime.Part(from: decoded.data).body.utf8String.hasPrefix("ISP support reference 1042\r\n"))
    }

    @Test func pgpMimeEncryptedFromKnownKey() throws {
        let (decoded, backend) = try decode("pgpmime-encrypted-known")
        #expect(decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.good])
        #expect(decoded.signingError == nil)

        guard case .decrypt(let input) = try #require(backend.recordedCalls.first) else {
            Issue.record("Expected a decrypt call")
            return
        }
        #expect(input.utf8String.hasPrefix("-----BEGIN PGP MESSAGE-----"))

        // The decoded message is the outer headers plus the decrypted multipart/mixed entity
        let message = Mime.Part(from: decoded.data)
        #expect(message.contentType?.is("multipart", "mixed") == true)
        #expect(message.boundary == "INNER-MIXED-98765")
        let parts = message.parts
        #expect(parts.count == 2)
        #expect(parts.first?.decodedBody.utf8String == "Café, naïve, £5 — ✓\nYour invoice is attached.\n")
        let pdf = try #require(parts.last)
        #expect(pdf.contentType?.is("application", "pdf") == true)
        #expect(pdf.headers.contentDisposition?.filename == "invoice.pdf")
        #expect(pdf.decodedBody.starts(with: Data("%PDF-1.4".utf8)))
        #expect(pdf.decodedBody.utf8String.contains("GPGMail test invoice 1042"))
    }

    @Test func pgpMimeEncryptedFromUnknownKeyStillDecrypts() throws {
        let (decoded, _) = try decode("pgpmime-encrypted-unknown")
        #expect(decoded.isEncrypted)
        let signature = try #require(decoded.signatures.first)
        #expect(signature.status == .unknownKey(keyID: Self.strangerKeyID))
        #expect(signature.fingerprint == "0DC7DC552112995328A4267412F87CD7AE0B268B")
        #expect(Mime.Part(from: decoded.data).parts.count == 2)
    }

    @Test func pgpMimeSignedVerifiesTheExactSignedBytes() throws {
        let (decoded, backend) = try decode("pgpmime-signed")
        #expect(!decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.good])
        #expect(decoded.signatures.first?.hashAlgorithm?.micalg == "pgp-sha256")

        // RFC 3156: the first part up to, not including, the CRLF before the delimiter
        let expected = Data("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\nSigned invoice notice 1042.\r\nCafé, naïve, £5 — ✓\r\n".utf8)
        guard case .verify(let signature, let signedData) = try #require(backend.recordedCalls.first) else {
            Issue.record("Expected a verify call")
            return
        }
        #expect(signedData == expected)
        #expect(signature.utf8String.hasPrefix("-----BEGIN PGP SIGNATURE-----"))

        let message = Mime.Part(from: decoded.data)
        #expect(message.contentType?.is("text", "plain") == true)
        #expect(message.body.utf8String == "Signed invoice notice 1042.\r\nCafé, naïve, £5 — ✓\r\n")
    }

    @Test func pgpMimeSignedWithChangedBodyIsBad() throws {
        let (decoded, _) = try decode("pgpmime-signed-bad")
        #expect(decoded.signatures.map(\.status) == [.bad])
        #expect(decoded.signatures.first?.signerEmail == "ollie@ollies.email")
        #expect(decoded.signingError == .invalidSignature(.bad))
        #expect(Mime.Part(from: decoded.data).body.utf8String.hasPrefix("Signed invoice notice 1043."))
    }

    @Test func inlineClearSigned() throws {
        let (decoded, backend) = try decode("inline-clearsigned")
        #expect(!decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.good])
        guard case .verifyClearSigned(let input) = try #require(backend.recordedCalls.first) else {
            Issue.record("Expected a clear-signed verify call")
            return
        }
        #expect(input.utf8String.hasPrefix("-----BEGIN PGP SIGNED MESSAGE-----\r\n"))
        #expect(input.utf8String.hasSuffix("-----END PGP SIGNATURE-----\r\n"))
        let message = Mime.Part(from: decoded.data)
        #expect(message.headers["Content-Type"] == "text/plain; charset=UTF-8")
        #expect(message.body.utf8String == "Clear-signed notice 1042.\r\nCafé, naïve, £5 — ✓\r\n")
    }

    @Test func decryptionFailureThrowsWithGPGsReason() throws {
        let run = GPGRun(output: Data(), statusText: "[GNUPG:] ENC_TO 816B947186876E19 18 0\n[GNUPG:] NO_SECKEY 816B947186876E19\n[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] DECRYPTION_FAILED\n[GNUPG:] END_DECRYPTION\n", errorOutput: Data("gpg: decryption failed: No secret key\n".utf8), exitCode: 2)
        #expect(run.status.missingSecretKeys == ["816B947186876E19"])
        let decoder = MessageDecoder(backend: FixtureBackend(run: run))
        for name in ["inline-encrypted-known", "pgpmime-encrypted-known"] {
            #expect(throws: PGPError.decryptionFailed("gpg: decryption failed: No secret key")) {
                try decoder.decode(Fixture.data("\(name).eml"))
            }
        }
    }

    @Test func signedInsideEncryptedSurfacesTheInnerSignature() throws {
        // Encrypt the signed fixture's multipart/signed entity with the stub, then decode it
        let signedMessage = Mime.Part(from: try Fixture.data("pgpmime-signed.eml"))
        let signedEntity = MimeWriter(headers: Mime.Headers(signedMessage.headers.fields.filter(\.isContentField)), body: signedMessage.body).data
        let stub = StubBackend()
        let ciphertext = try stub.encrypt(signedEntity, to: [PGPKey(fingerprint: "RECIPIENT")], signedBy: nil)
        let encrypted = MimeWriter(headers: Mime.Headers([Mime.Header(name: "Subject", value: "nested")]), multipart: "encrypted", parameters: [("protocol", "application/pgp-encrypted")], parts: [MessageEncoder.versionPart, MimeWriter(body: Mime.canonicalCRLF(ciphertext)).data]).data

        // The stub only knows the signed bytes once something has signed them
        let signedBytes = try #require(signedMessage.parts.first).raw
        _ = try stub.sign(signedBytes, with: PGPKey(fingerprint: "SIGNER"))

        let decoded = try #require(try MessageDecoder(backend: stub).decode(encrypted))
        #expect(decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.good])
        let message = Mime.Part(from: decoded.data)
        #expect(message.headers["Subject"] == "nested")
        #expect(message.contentType?.is("text", "plain") == true)
        #expect(message.body.utf8String.hasPrefix("Signed invoice notice 1042."))
    }
}
