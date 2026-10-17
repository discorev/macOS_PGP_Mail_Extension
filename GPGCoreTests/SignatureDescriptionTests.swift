//
//  SignatureDescriptionTests.swift
//  GPGCoreTests
//

import Foundation
import Testing
@testable import GPGCore

struct SignatureDescriptionTests {
    @Test func shortFingerprintIsTheLastSixteenDigitsInFours() {
        #expect(Fingerprint.short("0123456789ABCDEF0123456789abcdef01234567") == "89AB CDEF 0123 4567")
    }

    @Test func groupingIgnoresExistingSpacesAndCase() {
        #expect(Fingerprint.grouped("0123 4567 89ab cdef 0123") == "0123 4567 89AB CDEF 0123")
        #expect(Fingerprint.grouped("ABCDEF") == "ABCD EF")
        #expect(Fingerprint.short("ABCDEF") == "ABCD EF")
    }

    @Test(arguments: [KeyValidity.full, .ultimate])
    func goodSignatureFromACertifiedKeyIsValid(validity: KeyValidity) {
        let description = SignatureDescription(Signature(status: .good, validity: validity))
        #expect(description.tone == .valid)
        #expect(description.title == "Valid signature")
        #expect(description.subtitle == nil)
        #expect(description.advice == nil)
    }

    @Test(arguments: [KeyValidity.unknown, .undefined, .marginal])
    func goodSignatureFromAnUncertifiedKeySaysSo(validity: KeyValidity) {
        let description = SignatureDescription(Signature(status: .good, validity: validity))
        #expect(description.tone == .caution)
        #expect(description.title == "Valid signature")
        #expect(description.subtitle == "This key isn't certified")
        #expect(description.advice?.contains("GPG Keychain") == true)
    }

    @Test func problemsHaveTheirOwnTitles() {
        let titles: [(Signature.Status, String, SignatureDescription.Tone)] = [
            (.bad, "This signature doesn't match the message", .invalid),
            (.unknownKey(keyID: "0123456789ABCDEF"), "Signed by a key you don't have", .caution),
            (.expiredSignature, "This signature has expired", .caution),
            (.expiredKey, "Signed with an expired key", .caution),
            (.revokedKey, "Signed with a revoked key", .invalid),
            (.error(code: 4), "This signature couldn't be checked", .invalid),
        ]
        for (status, title, tone) in titles {
            let description = SignatureDescription(Signature(status: status, validity: .full))
            #expect(description.title == title)
            #expect(description.tone == tone)
            #expect(description.advice != nil)
        }
    }

    @Test func algorithmSummaryNamesWhatItKnows() {
        #expect(Signature(status: .good, publicKeyAlgorithm: .init(rawValue: 1), hashAlgorithm: .init(rawValue: 8)).algorithmSummary == "RSA · SHA256")
        #expect(Signature(status: .good, hashAlgorithm: .init(rawValue: 10)).algorithmSummary == "SHA512")
        #expect(Signature(status: .good).algorithmSummary == nil)
    }
}
