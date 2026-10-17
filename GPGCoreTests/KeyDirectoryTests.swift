//
//  KeyDirectoryTests.swift
//  GPGCoreTests
//

import Foundation
import Testing
@testable import GPGCore

struct KeyDirectoryTests {
    /// A modern key: the primary key signs and certifies, a subkey encrypts
    private func modernKey(_ fingerprint: String = "PRIMARY", emails: [String] = ["ollie@ollies.email"], secret: Bool = true, created: Date? = nil, unusable: Bool = false, subkeyUnusable: Bool = false) -> KeyringKey {
        KeyringKey(fingerprint: fingerprint, emails: emails, hasSecretKey: secret, canAnySign: true, canAnyEncrypt: true, isUnusable: unusable, created: created, components: [
            .init(fingerprint: fingerprint, canSign: true, canEncrypt: false, isUnusable: unusable),
            .init(fingerprint: "\(fingerprint)-SUB", canSign: false, canEncrypt: true, isUnusable: subkeyUnusable),
        ])
    }

    @Test func encryptionUsesASubkey() {
        let directory = KeyDirectory(keys: [modernKey()])
        #expect(directory.encryptionKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "PRIMARY"))
        #expect(directory.signingKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "PRIMARY"))
    }

    @Test func emailsMatchIgnoringCaseOnBothSides() {
        let directory = KeyDirectory(keys: [modernKey(emails: ["Ollie@Ollies.Email"])])
        #expect(directory.encryptionKey(for: "OLLIE@ollies.email") == PGPKey(fingerprint: "PRIMARY"))
        #expect(directory.signingKey(for: " ollie@OLLIES.email") == PGPKey(fingerprint: "PRIMARY"))
        #expect(directory.signingKey(for: "someone@ollies.email") == nil)
    }

    @Test func expiredRevokedOrDisabledKeysAreSkipped() {
        let directory = KeyDirectory(keys: [modernKey(unusable: true)])
        #expect(directory.signingKey(for: "ollie@ollies.email") == nil)
        #expect(directory.encryptionKey(for: "ollie@ollies.email") == nil)
    }

    @Test func keysWhoseEncryptionSubkeysHaveAllExpiredCantEncrypt() {
        let directory = KeyDirectory(keys: [modernKey(subkeyUnusable: true)])
        #expect(directory.encryptionKey(for: "ollie@ollies.email") == nil)
        #expect(directory.signingKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "PRIMARY"))
    }

    @Test func onlySecretKeysSign() {
        let directory = KeyDirectory(keys: [modernKey(secret: false)])
        #expect(directory.signingKey(for: "ollie@ollies.email") == nil)
        #expect(directory.encryptionKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "PRIMARY"))
    }

    @Test func capabilityFlagsAreRespected() {
        var key = modernKey()
        key.canAnyEncrypt = false
        key.canAnySign = false
        let directory = KeyDirectory(keys: [key])
        #expect(directory.signingKey(for: "ollie@ollies.email") == nil)
        #expect(directory.encryptionKey(for: "ollie@ollies.email") == nil)
    }

    @Test func newestUsableKeyWins() {
        let old = modernKey("OLD", created: Date(timeIntervalSince1970: 1_000))
        let new = modernKey("NEW", created: Date(timeIntervalSince1970: 2_000))
        let newButExpired = modernKey("NEWEST", created: Date(timeIntervalSince1970: 3_000), unusable: true)
        for keys in [[old, new, newButExpired], [newButExpired, new, old]] {
            let directory = KeyDirectory(keys: keys)
            #expect(directory.encryptionKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "NEW"))
            #expect(directory.signingKey(for: "ollie@ollies.email") == PGPKey(fingerprint: "NEW"))
        }
    }

    @Test func emailsForAnySubkeyFingerprint() {
        let directory = KeyDirectory(keys: [modernKey(emails: ["ollie@ollies.email", "ollie@example.invalid"])])
        #expect(directory.emails(forFingerprint: "primary-sub") == ["ollie@ollies.email", "ollie@example.invalid"])
        #expect(directory.emails(forFingerprint: "UNKNOWN").isEmpty)
    }
}
