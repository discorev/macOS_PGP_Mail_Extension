//
//  MimeTests.swift
//  GPGCoreTests
//

import Foundation
import Testing
@testable import GPGCore

struct MimeTests {
    @Test(arguments: ["plain"] + Fixture.cases)
    func parsedMessagesWriteBackByteForByte(name: String) throws {
        let original = try Fixture.data("\(name).eml")
        let part = Mime.Part(from: original)
        #expect(MimeWriter(headers: part.headers, body: part.body).data == original)
    }

    @Test func multipartRoundTripThroughTheWriter() throws {
        let first = Data("Content-Type: text/plain\r\n\r\nHello\r\n".utf8)
        let second = Data("Content-Type: application/octet-stream\r\n\r\nno trailing newline".utf8)
        let headers = Mime.Headers([Mime.Header(name: "Subject", value: "Round trip")])
        let written = MimeWriter(headers: headers, multipart: "mixed", parameters: [("charset", "x")], parts: [first, second], boundary: "BOUNDARY").data

        #expect(written.utf8String == "Subject: Round trip\r\nContent-Type: multipart/mixed; charset=\"x\"; boundary=\"BOUNDARY\"\r\n\r\n--BOUNDARY\r\nContent-Type: text/plain\r\n\r\nHello\r\n\r\n--BOUNDARY\r\nContent-Type: application/octet-stream\r\n\r\nno trailing newline\r\n--BOUNDARY--\r\n")

        let parsed = Mime.Part(from: written)
        #expect(parsed.boundary == "BOUNDARY")
        #expect(parsed.parts.map(\.raw) == [first, second])
        #expect(parsed.parts.last?.body.utf8String == "no trailing newline")
    }

    @Test func multipartWithLFLineEndings() {
        let message = Data("Content-Type: multipart/mixed; boundary=b\n\npreamble\n--b\nContent-Type: text/plain\n\none\n--b\n\ntwo\n--b--\nepilogue\n".utf8)
        let parts = Mime.Part(from: message).parts
        #expect(parts.map(\.body.utf8String) == ["one", "two"])
        #expect(parts.first?.contentType?.is("text", "plain") == true)
        #expect(parts.last?.headers.fields.isEmpty == true)
    }

    @Test func boundaryMustStartALineAndNotBeAPrefix() {
        let message = Data("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\ntext mentioning --b inline\r\n--bb not a delimiter\r\n--b--\r\n".utf8)
        let parts = Mime.Part(from: message).parts
        #expect(parts.map(\.body.utf8String) == ["text mentioning --b inline\r\n--bb not a delimiter"])
    }

    @Test func missingCloseDelimiterKeepsTheLastPart() {
        let message = Data("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\none\r\n--b\r\n\r\ntruncated".utf8)
        #expect(Mime.Part(from: message).parts.map(\.body.utf8String) == ["one", "truncated"])
    }

    @Test func foldedHeadersAndParameters() throws {
        let message = Data("Content-Type: multipart/signed;\r\n\tprotocol=\"application/pgp-signature\";\r\n micalg=PGP-SHA256; boundary=\"a;b\"\r\nX-Other: 1\r\n\r\nbody".utf8)
        let part = Mime.Part(from: message)
        let contentType = try #require(part.contentType)
        #expect(contentType.is("multipart", "signed"))
        #expect(contentType.parameters == ["protocol": "application/pgp-signature", "micalg": "PGP-SHA256", "boundary": "a;b"])
        #expect(part.headers["x-other"] == "1")
        #expect(part.body.utf8String == "body")
    }

    @Test func caseInsensitiveTypes() {
        let contentType = Mime.ContentType("Multipart/Encrypted; Protocol=\"application/pgp-encrypted\"")
        #expect(contentType.type == "multipart")
        #expect(contentType.subtype == "encrypted")
        #expect(contentType.parameters["protocol"] == "application/pgp-encrypted")
    }

    @Test func longGeneratedHeadersAreFoldedAndReadBack() throws {
        let value = Mime.ContentType.value("multipart/signed", [("micalg", "pgp-sha256"), ("protocol", "application/pgp-signature"), ("boundary", "GPGMail-00000000-0000-0000-0000-000000000000")])
        let written = MimeWriter(headers: Mime.Headers([Mime.Header(name: "Content-Type", value: value)])).data
        #expect(written.utf8String.split(separator: "\r\n").allSatisfy { $0.count <= 78 })
        let contentType = try #require(Mime.Part(from: written).contentType)
        #expect(contentType.boundary == "GPGMail-00000000-0000-0000-0000-000000000000")
        #expect(contentType.parameters["micalg"] == "pgp-sha256")
    }

    @Test func dataWithoutHeadersIsAllBody() {
        let text = Data("ISP support reference 1042\nNote: this looks like a header\n".utf8)
        let part = Mime.Part(from: text)
        #expect(part.headers.fields.isEmpty)
        #expect(part.body == text)

        let leadingBlank = Mime.Part(from: Data("\r\nbody".utf8))
        #expect(leadingBlank.headers.fields.isEmpty)
        #expect(leadingBlank.body.utf8String == "body")
    }

    @Test(arguments: ["", "\r\n", "Content-Type:", "Content-Type: ;;;\r\n\r\n", "Content-Type: /\r\n\r\n", ":\r\n\r\n", "Content-Type: multipart/mixed\r\n\r\n--x", "Content-Type: multipart/mixed; boundary=\r\n\r\n", "Content-Type: multipart/mixed; boundary=\"x\r\n\r\n--x\r\n", "Content-Disposition: \r\n\r\n", "Content-Type: text/plain; name=\"unterminated\r\n\r\n"])
    func malformedInputNeverCrashes(text: String) {
        let part = Mime.Part(from: Data(text.utf8))
        _ = part.parts
        _ = part.headers.contentDisposition
        _ = part.decodedBody
        _ = MessageDecoder.kind(of: Data(text.utf8))
    }

    @Test func nonUTF8HeadersAreReadAsLatin1() {
        var message = Data("Subject: caf".utf8)
        message.append(0xE9)
        message.append(Data("\r\n\r\nbody".utf8))
        let part = Mime.Part(from: message)
        #expect(part.headers["Subject"] == "café")
        #expect(part.body.utf8String == "body")
        #expect(MimeWriter(headers: part.headers, body: part.body).data == message)
    }

    @Test func settingAHeaderKeepsItsPosition() {
        var headers = Mime.Headers([Mime.Header(name: "From", value: "a"), Mime.Header(name: "content-type", value: "x"), Mime.Header(name: "Subject", value: "s"), Mime.Header(name: "Content-Type", value: "y")])
        headers.set("Content-Type", "text/plain")
        #expect(headers.fields.map(\.name) == ["From", "Content-Type", "Subject"])
        #expect(headers["CONTENT-TYPE"] == "text/plain")
        headers.remove("from")
        #expect(headers.fields.map(\.name) == ["Content-Type", "Subject"])
    }

    @Test func transferEncodings() {
        #expect(Mime.decode(Data("Q2Fmw6k=\r\n".utf8), transferEncoding: "BASE64").utf8String == "Café")
        #expect(Mime.decode(Data("-----BEGIN PGP MESSAGE-----\r\n=3D0EVv\r\nsoft=\r\nbreak=\nlf =ZZ\r\n".utf8), transferEncoding: "quoted-printable").utf8String == "-----BEGIN PGP MESSAGE-----\r\n=0EVv\r\nsoftbreaklf =ZZ\r\n")
        #expect(Mime.decode(Data("as is".utf8), transferEncoding: "8bit").utf8String == "as is")
        #expect(Mime.decode(Data("as is".utf8), transferEncoding: nil).utf8String == "as is")
    }

    @Test func quotedPrintableInlineMessageIsRecognised() throws {
        let original = Mime.Part(from: try Fixture.data("inline-encrypted-known.eml"))
        var body = original.body.utf8String.replacingOccurrences(of: "=", with: "=3D")
        body = body.replacingOccurrences(of: "-----BEGIN", with: "-----BEG=\r\nIN")
        var headers = original.headers
        headers.append("Content-Transfer-Encoding", "quoted-printable")
        let message = MimeWriter(headers: headers, body: Data(body.utf8)).data
        #expect(MessageDecoder.kind(of: message) == .inlineEncrypted)
        let decoded = try #require(try MessageDecoder(backend: FixtureBackend(fixture: "inline-encrypted-known")).decode(message))
        let rebuilt = Mime.Part(from: decoded.data)
        #expect(rebuilt.headers.values(for: "Content-Transfer-Encoding") == ["8bit"])
    }

    @Test func quotedArmourIsNotInlinePGP() {
        let message = Data("Content-Type: text/plain\r\n\r\nYou wrote:\r\n> -----BEGIN PGP MESSAGE-----\r\n> abc\r\n> -----END PGP MESSAGE-----\r\n".utf8)
        #expect(MessageDecoder.kind(of: message) == nil)
        let attachment = Data("Content-Type: application/pgp-keys\r\n\r\n-----BEGIN PGP MESSAGE-----\r\n-----END PGP MESSAGE-----\r\n".utf8)
        #expect(MessageDecoder.kind(of: attachment) == nil)
    }

    @Test(arguments: ["Version: 1", "Version: 1\r\n", "Version: 1\n", "Version: 1  \r\n\r\n", "Version: 1\t"])
    func pgpMimeVersionIsAcceptedWithAnyLineEnding(version: String) throws {
        let message = MimeWriter(headers: Mime.Headers(), multipart: "encrypted", parameters: [("protocol", "application/pgp-encrypted")], parts: [
            Data("Content-Type: application/pgp-encrypted\r\n\r\n\(version)".utf8),
            Data("Content-Type: application/octet-stream\r\n\r\nCIPHERTEXT\r\n".utf8),
        ]).data
        #expect(try MessageDecoder.encryptedPayload(of: Mime.Part(from: message)).utf8String == "CIPHERTEXT\r\n")
    }

    @Test func unsupportedPGPMimeVersionIsRejected() {
        let message = MimeWriter(headers: Mime.Headers(), multipart: "encrypted", parameters: [("protocol", "application/pgp-encrypted")], parts: [
            Data("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 2\r\n".utf8),
            Data("Content-Type: application/octet-stream\r\n\r\nCIPHERTEXT\r\n".utf8),
        ]).data
        #expect(throws: PGPError.malformedMessage("unsupported PGP/MIME version \"Version: 2\"")) {
            try MessageDecoder.encryptedPayload(of: Mime.Part(from: message))
        }
    }
}
