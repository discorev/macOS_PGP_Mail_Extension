//
//  LineEndingTests.swift
//  GPGCoreTests
//
//  The MailKit edge hands everything to Mime.canonicalCRLF. What Mail 27 passes hasn't been captured,
//  so it has to cope with LF-only, CRLF and mixed input.
//

import Foundation
import Testing
@testable import GPGCore

struct LineEndingTests {
    @Test(arguments: [
        ("a\nb\n", "a\r\nb\r\n"),
        ("a\r\nb\r\n", "a\r\nb\r\n"),
        ("a\r\nb\nc\r\n\n", "a\r\nb\r\nc\r\n\r\n"),
        ("\n\n", "\r\n\r\n"),
        ("lone\rCR\r", "lone\rCR\r"),
        ("no line ending", "no line ending"),
        ("", ""),
    ])
    func convertsToCRLF(input: String, expected: String) {
        let converted = Mime.canonicalCRLF(Data(input.utf8))
        #expect(converted.utf8String == expected)
        // and never double-converts
        #expect(Mime.canonicalCRLF(converted) == converted)
    }

    @Test(arguments: ["plain"] + Fixture.cases)
    func lfOnlyFixturesComeBackByteForByte(name: String) throws {
        let original = try Fixture.data("\(name).eml")
        let lfOnly = Data(original.utf8String.replacingOccurrences(of: "\r\n", with: "\n").utf8)
        #expect(Mime.canonicalCRLF(lfOnly) == original)
    }

    @Test func lfOnlySignedMessageVerifiesTheSameBytes() throws {
        let original = try Fixture.data("pgpmime-signed.eml")
        let lfOnly = Data(original.utf8String.replacingOccurrences(of: "\r\n", with: "\n").utf8)

        let fromCRLF = try FixtureBackend(fixture: "pgpmime-signed")
        let fromLF = try FixtureBackend(fixture: "pgpmime-signed")
        _ = try MessageDecoder(backend: fromCRLF).decode(original)
        _ = try MessageDecoder(backend: fromLF).decode(Mime.canonicalCRLF(lfOnly))
        #expect(!fromLF.recordedCalls.isEmpty)
        #expect(fromLF.recordedCalls == fromCRLF.recordedCalls)
    }

    @Test func lfOnlyOutgoingMessageIsSignedAsCRLF() throws {
        let backend = StubBackend(signingKeys: ["ollie@ollies.email": "SENDER-FPR"])
        let lfOnly = Data("From: ollie@ollies.email\nSubject: LF\nContent-Type: text/plain\n\nLine one\nLine two\n".utf8)
        let encoded = try MessageEncoder(backend: backend).encode(Mime.canonicalCRLF(lfOnly), sender: "ollie@ollies.email", recipients: [], sign: true, encrypt: false)
        #expect(backend.signed == [Data("Content-Type: text/plain\r\n\r\nLine one\r\nLine two\r\n".utf8)])
        #expect(!encoded.hasBareLineFeed)
    }
}
