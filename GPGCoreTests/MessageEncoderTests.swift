//
//  MessageEncoderTests.swift
//  GPGCoreTests
//
//  RFC 3156 structure of what the encoder produces, using a stub backend with recognisable output.
//

import Foundation
import Testing
@testable import GPGCore

struct MessageEncoderTests {
    static let sender = "ollie@ollies.email"
    static let recipient = "friend@example.invalid"
    static let message = Data("""
        From: Ollie <ollie@ollies.email>\r
        To: Friend <friend@example.invalid>\r
        Subject: Encoder test\r
        MIME-Version: 1.0\r
        Content-Type: text/plain; charset=UTF-8\r
        Content-Transfer-Encoding: quoted-printable\r
        \r
        Caf=C3=A9 at 5?\r
        See you there.\r

        """.utf8)

    private func stub() -> StubBackend {
        StubBackend(signingKeys: [Self.sender: "SENDER-FPR"], encryptionKeys: [Self.sender: "SENDER-FPR", Self.recipient: "FRIEND-FPR"])
    }

    /// The headers and body the encoder should wrap: just the Content-* fields
    static let entity = Data("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9 at 5?\r\nSee you there.\r\n".utf8)

    private func expectOuterHeaders(_ part: Mime.Part) {
        #expect(part.headers.fields.map(\.name) == ["From", "To", "Subject", "MIME-Version", "Content-Type"])
        #expect(part.headers["Content-Transfer-Encoding"] == nil)
    }

    @Test func signingProducesMultipartSigned() throws {
        let backend = stub()
        let encoded = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [Self.recipient], sign: true, encrypt: false)
        #expect(!encoded.hasBareLineFeed)

        let message = Mime.Part(from: encoded)
        expectOuterHeaders(message)
        let contentType = try #require(message.contentType)
        #expect(contentType.is("multipart", "signed"))
        #expect(contentType.parameters["protocol"] == "application/pgp-signature")
        #expect(contentType.parameters["micalg"] == "pgp-sha256")

        let parts = message.parts
        #expect(parts.count == 2)
        // The first part is exactly the bytes that were signed
        #expect(backend.signed == [Self.entity])
        #expect(parts.first?.raw == Self.entity)
        let signature = try #require(parts.last)
        #expect(signature.contentType?.is("application", "pgp-signature") == true)
        #expect(signature.body == Mime.canonicalCRLF(StubBackend.signature))

        // and it verifies when decoded again
        let decoded = try #require(try MessageDecoder(backend: backend).decode(encoded))
        #expect(decoded.signatures.map(\.status) == [.good])
        #expect(!decoded.isEncrypted)
        #expect(Mime.Part(from: decoded.data).decodedBody.utf8String == "Café at 5?\r\nSee you there.\r\n")
    }

    @Test func micalgFollowsTheHashGPGUsed() throws {
        let backend = StubBackend(signingKeys: [Self.sender: "SENDER-FPR"], hashAlgorithm: HashAlgorithm(rawValue: 10))
        let encoded = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [], sign: true, encrypt: false)
        #expect(Mime.Part(from: encoded).contentType?.parameters["micalg"] == "pgp-sha512")

        let unknown = StubBackend(signingKeys: [Self.sender: "SENDER-FPR"], hashAlgorithm: HashAlgorithm(rawValue: 99))
        #expect(throws: PGPError.signingFailed("Unknown hash algorithm 99.")) {
            try MessageEncoder(backend: unknown).encode(Self.message, sender: Self.sender, recipients: [], sign: true, encrypt: false)
        }
    }

    @Test func encryptingProducesMultipartEncrypted() throws {
        let backend = stub()
        let encoded = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [Self.recipient], sign: false, encrypt: true)
        #expect(!encoded.hasBareLineFeed)

        let message = Mime.Part(from: encoded)
        expectOuterHeaders(message)
        let contentType = try #require(message.contentType)
        #expect(contentType.is("multipart", "encrypted"))
        #expect(contentType.parameters["protocol"] == "application/pgp-encrypted")

        let parts = message.parts
        #expect(parts.count == 2)
        #expect(parts.first?.contentType?.is("application", "pgp-encrypted") == true)
        #expect(parts.first?.body.utf8String == "Version: 1\r\n")
        #expect(parts.last?.contentType?.is("application", "octet-stream") == true)
        #expect(parts.last?.body.utf8String == "-----BEGIN PGP MESSAGE-----\r\nFAKE-CIPHERTEXT-0\r\n-----END PGP MESSAGE-----\r\n")

        let encryption = try #require(backend.encrypted.first)
        #expect(encryption.plaintext == Self.entity)
        #expect(encryption.recipients.contains(PGPKey(fingerprint: "FRIEND-FPR")))
        #expect(encryption.signer == nil)
        #expect(backend.signed.isEmpty)

        let decoded = try #require(try MessageDecoder(backend: backend).decode(encoded))
        #expect(decoded.isEncrypted)
        #expect(decoded.signatures.isEmpty)
        let plaintext = Mime.Part(from: decoded.data)
        #expect(plaintext.headers["Subject"] == "Encoder test")
        #expect(plaintext.headers["Content-Transfer-Encoding"] == "quoted-printable")
        #expect(plaintext.decodedBody.utf8String == "Café at 5?\r\nSee you there.\r\n")
    }

    @Test func encryptsToTheSenderToo() throws {
        let backend = stub()
        _ = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [Self.recipient], sign: false, encrypt: true)
        // Sending to yourself doesn't add your key twice
        _ = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [Self.sender, Self.recipient], sign: false, encrypt: true)
        // Without a key of your own, it still encrypts to the recipients
        _ = try MessageEncoder(backend: backend).encode(Self.message, sender: "keyless@example.invalid", recipients: [Self.recipient], sign: false, encrypt: true)
        #expect(backend.encrypted.map(\.recipients) == [
            [PGPKey(fingerprint: "FRIEND-FPR"), PGPKey(fingerprint: "SENDER-FPR")],
            [PGPKey(fingerprint: "SENDER-FPR"), PGPKey(fingerprint: "FRIEND-FPR")],
            [PGPKey(fingerprint: "FRIEND-FPR")],
        ])
    }

    @Test func signingAndEncryptingIsOneCall() throws {
        let backend = stub()
        let encoded = try MessageEncoder(backend: backend).encode(Self.message, sender: Self.sender, recipients: [Self.recipient], sign: true, encrypt: true)
        #expect(Mime.Part(from: encoded).contentType?.is("multipart", "encrypted") == true)
        #expect(backend.encrypted.map(\.signer) == [PGPKey(fingerprint: "SENDER-FPR")])
        #expect(backend.signed.isEmpty)

        let decoded = try #require(try MessageDecoder(backend: backend).decode(encoded))
        #expect(decoded.isEncrypted)
        #expect(decoded.signatures.map(\.status) == [.good])
    }

    @Test func missingKeysAreReportedForTheRightStep() {
        let encoder = MessageEncoder(backend: stub())
        #expect(throws: PGPError.noSigningKey("someone@example.invalid")) {
            try encoder.encode(Self.message, sender: "someone@example.invalid", recipients: [Self.recipient], sign: true, encrypt: true)
        }
        #expect(PGPError.noSigningKey("x").isSigningError)

        #expect(throws: PGPError.noEncryptionKey(["stranger@example.invalid"])) {
            try encoder.encode(Self.message, sender: Self.sender, recipients: [Self.recipient, "stranger@example.invalid"], sign: false, encrypt: true)
        }
        #expect(!PGPError.noEncryptionKey([]).isSigningError)
    }

    @Test func neitherSigningNorEncryptingLeavesTheMessageAlone() throws {
        #expect(try MessageEncoder(backend: stub()).encode(Self.message, sender: Self.sender, recipients: [], sign: false, encrypt: false) == Self.message)
    }

    @Test func encodingStatus() {
        let encoder = MessageEncoder(backend: stub())
        #expect(encoder.status(sender: Self.sender, recipients: [Self.recipient]) == .init(canSign: true, canEncrypt: true, addressesFailingEncryption: []))
        #expect(encoder.status(sender: Self.sender, recipients: [Self.recipient, "stranger@example.invalid"]) == .init(canSign: true, canEncrypt: true, addressesFailingEncryption: ["stranger@example.invalid"]))
        #expect(encoder.status(sender: "someone@example.invalid", recipients: ["stranger@example.invalid"]) == .init(canSign: false, canEncrypt: false, addressesFailingEncryption: []))
    }
}
