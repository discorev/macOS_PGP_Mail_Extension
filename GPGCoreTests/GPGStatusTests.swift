//
//  GPGStatusTests.swift
//  GPGCoreTests
//

import Foundation
import Testing
@testable import GPGCore

struct GPGStatusTests {
    @Test func errsigWithExitCode2IsDecryptedButSignedByUnknownKey() throws {
        let run = try Fixture.run("pgpmime-encrypted-unknown")
        #expect(run.exitCode == 2)
        #expect(run.status.isDecrypted)

        let result = try run.decrypted()
        #expect(result.data == run.output)
        let signature = try #require(result.signatures.first)
        #expect(result.signatures.count == 1)
        #expect(signature.status == .unknownKey(keyID: "12F87CD7AE0B268B"))
        #expect(signature.keyID == "12F87CD7AE0B268B")
        #expect(signature.fingerprint == "0DC7DC552112995328A4267412F87CD7AE0B268B")
        #expect(signature.publicKeyAlgorithm == PublicKeyAlgorithm(rawValue: 22))
        #expect(signature.hashAlgorithm == HashAlgorithm(rawValue: 10))
        #expect(signature.created == Date(timeIntervalSince1970: 1792234984))
        #expect(signature.signerName == nil)
    }

    @Test func goodSignatureDetails() throws {
        let status = GPGStatus(parsing: String(decoding: try Fixture.data("inline-clearsigned.status"), as: UTF8.self))
        let signature = try #require(status.signatures.first)
        #expect(status.signatures.count == 1)
        #expect(!status.isDecrypted)
        #expect(signature.status == .good)
        #expect(signature.keyID == "ABEC72A4721178F2")
        #expect(signature.signerName == "GPGMail Extension TEST KEY")
        #expect(signature.signerEmail == "ollie@ollies.email")
        #expect(signature.fingerprint == "17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2")
        #expect(signature.primaryKeyFingerprint == "17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2")
        #expect(signature.created == Date(timeIntervalSince1970: 1792234984))
        #expect(signature.expires == nil)
        #expect(signature.validity == .ultimate)
        #expect(signature.hashAlgorithm?.name == "SHA256")
    }

    @Test func unknownAlgorithmNumbersDecodeAsUnknown() throws {
        let status = GPGStatus(parsing: """
            [GNUPG:] NEWSIG
            [GNUPG:] GOODSIG ABEC72A4721178F2 Someone <someone@example.invalid>
            [GNUPG:] VALIDSIG 17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2 2026-10-17 1792234984 0 4 0 99 77 00 17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2
            """)
        let signature = try #require(status.signatures.first)
        #expect(signature.status == .good)
        #expect(signature.publicKeyAlgorithm?.rawValue == 99)
        #expect(signature.publicKeyAlgorithm?.name == nil)
        #expect(signature.hashAlgorithm?.rawValue == 77)
        #expect(signature.hashAlgorithm?.name == nil)
        #expect(signature.hashAlgorithm?.micalg == nil)
        // and survives the JSON round trip used for Mail's signer context
        let decoded = try JSONDecoder().decode(Signature.self, from: JSONEncoder().encode(signature))
        #expect(decoded == signature)
    }

    @Test func errsigWithOtherCodesIsAnError() throws {
        let status = GPGStatus(parsing: "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG 12F87CD7AE0B268B 99 10 00 1792234984 4 -\n")
        let signature = try #require(status.signatures.first)
        #expect(signature.status == .error(code: 4))
        #expect(signature.fingerprint == nil)
        #expect(signature.publicKeyAlgorithm?.name == nil)
    }

    @Test func expiredAndRevokedKeys() {
        let status = GPGStatus(parsing: """
            [GNUPG:] NEWSIG
            [GNUPG:] EXPKEYSIG AAAAAAAAAAAAAAAA Old Key <old@example.invalid>
            [GNUPG:] NEWSIG
            [GNUPG:] REVKEYSIG BBBBBBBBBBBBBBBB Revoked Key <revoked@example.invalid>
            [GNUPG:] NEWSIG
            [GNUPG:] EXPSIG CCCCCCCCCCCCCCCC Expired Signature <expired@example.invalid>
            """)
        #expect(status.signatures.map(\.status) == [.expiredKey, .revokedKey, .expiredSignature])
        #expect(status.signatures.map(\.signerEmail) == ["old@example.invalid", "revoked@example.invalid", "expired@example.invalid"])
    }

    @Test func signaturesWithoutNewsigAreKeptApart() {
        let status = GPGStatus(parsing: """
            [GNUPG:] GOODSIG AAAAAAAAAAAAAAAA First <first@example.invalid>
            [GNUPG:] TRUST_FULLY 0 pgp
            [GNUPG:] BADSIG BBBBBBBBBBBBBBBB Second <second@example.invalid>
            """)
        #expect(status.signatures.map(\.status) == [.good, .bad])
        #expect(status.signatures.map(\.validity) == [.full, .unknown])
    }

    @Test func userIDsAreUnescapedAndSplit() throws {
        let status = GPGStatus(parsing: "[GNUPG:] GOODSIG AAAAAAAAAAAAAAAA Zo%C3%AB 100%25 (work) <zoe@example.invalid>\n")
        let signature = try #require(status.signatures.first)
        #expect(signature.signerName == "Zoë 100%")
        #expect(signature.signerEmail == "zoe@example.invalid")
        #expect(GPGStatus.nameAndEmail(from: "no-email-here") == ("no-email-here", nil))
        #expect(GPGStatus.nameAndEmail(from: "<only@example.invalid>") == (nil, "only@example.invalid"))
    }

    @Test func malformedLinesNeverCrash() {
        let status = GPGStatus(parsing: """
            not a status line
            [GNUPG:]
            [GNUPG:] VALIDSIG
            [GNUPG:] ERRSIG
            [GNUPG:] GOODSIG
            [GNUPG:] TRUST_ULTIMATE
            [GNUPG:] VALIDSIG x y notanumber z q r s t u
            [GNUPG:] SIG_CREATED D
            [GNUPG:] NO_SECKEY
            [GNUPG:] FAILURE
            """)
        #expect(status.signatures.count == 2)
        #expect(status.createdSignatureHash == nil)
        #expect(status.missingSecretKeys.isEmpty)
    }

    @Test func detachedSignatureNeedsSigCreated() throws {
        let armor = Data("-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----\n".utf8)
        let good = GPGRun(output: armor, statusText: "[GNUPG:] KEY_CONSIDERED X 0\n[GNUPG:] SIG_CREATED D 22 8 00 1792234984 17AC59CCCC8AC3BDDDCC21D1ABEC72A4721178F2\n", errorOutput: Data(), exitCode: 0)
        #expect(try good.detachedSignature() == DetachedSignature(armored: armor, hashAlgorithm: HashAlgorithm(rawValue: 8)))

        let cancelled = GPGRun(output: Data(), statusText: "[GNUPG:] FAILURE sign 83886179\n", errorOutput: Data("gpg: signing failed: Operation cancelled\n".utf8), exitCode: 2)
        #expect(throws: PGPError.signingFailed("gpg: signing failed: Operation cancelled")) {
            try cancelled.detachedSignature()
        }
    }

    @Test func encryptionFailuresAreAttributedToTheRightStep() throws {
        let armor = Data("-----BEGIN PGP MESSAGE-----\n...\n-----END PGP MESSAGE-----\n".utf8)
        let okay = GPGRun(output: armor, statusText: "[GNUPG:] BEGIN_ENCRYPTION 2 9\n[GNUPG:] SIG_CREATED S 22 10 00 1792234984 X\n[GNUPG:] END_ENCRYPTION\n", errorOutput: Data(), exitCode: 0)
        #expect(try okay.encrypted(signed: true) == armor)

        let badRecipient = GPGRun(output: Data(), statusText: "[GNUPG:] INV_RECP 10 someone@example.invalid\n[GNUPG:] FAILURE encrypt 53\n", errorOutput: Data("gpg: someone@example.invalid: skipped: Unusable public key\n".utf8), exitCode: 2)
        #expect(throws: PGPError.encryptionFailed("gpg: someone@example.invalid: skipped: Unusable public key")) {
            try badRecipient.encrypted(signed: true)
        }

        let signingCancelled = GPGRun(output: Data(), statusText: "[GNUPG:] FAILURE sign 83886179\n", errorOutput: Data("gpg: signing failed: Operation cancelled\n".utf8), exitCode: 2)
        #expect(throws: PGPError.signingFailed("gpg: signing failed: Operation cancelled")) {
            try signingCancelled.encrypted(signed: true)
        }

        let noReason = GPGRun(output: Data(), statusText: "", errorOutput: Data(), exitCode: 2)
        #expect(throws: PGPError.encryptionFailed("gpg exited with status 2.")) {
            try noReason.encrypted(signed: false)
        }
    }

    @Test func verificationWithoutSignaturesFails() {
        let run = GPGRun(output: Data(), statusText: "[GNUPG:] NODATA 1\n", errorOutput: Data("gpg: no valid OpenPGP data found.\n".utf8), exitCode: 2)
        #expect(throws: PGPError.verificationFailed("gpg: no valid OpenPGP data found.")) {
            try run.verified()
        }
        #expect(PGPError.verificationFailed("gpg: no valid OpenPGP data found.").errorDescription?.contains("no valid OpenPGP data") == true)
    }
}
