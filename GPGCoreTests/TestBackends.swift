//
//  TestBackends.swift
//  GPGCoreTests
//

import Foundation
import Synchronization
@testable import GPGCore

/// Loads the recorded fixtures in GPGCoreTests/Fixtures (see the README there)
enum Fixture {
    static let cases = ["inline-encrypted-known", "inline-encrypted-unknown", "pgpmime-encrypted-known", "pgpmime-encrypted-unknown", "pgpmime-signed", "pgpmime-signed-bad", "inline-clearsigned"]

    private final class BundleToken {}

    static func url(_ name: String) throws -> URL {
        let bundle = Bundle(for: BundleToken.self)
        guard let directory = bundle.url(forResource: "Fixtures", withExtension: nil) else {
            throw CocoaError(.fileNoSuchFile)
        }
        return directory.appendingPathComponent(name)
    }

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: url(name))
    }

    /// The recorded gpg run for a case: its `.decrypted` output (if any), `.status` lines and `.exit` code
    static func run(_ name: String) throws -> GPGRun {
        let output = (try? data("\(name).decrypted")) ?? Data()
        let status = String(decoding: try data("\(name).status"), as: UTF8.self)
        let exit = String(decoding: try data("\(name).exit"), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        return GPGRun(output: output, statusText: status, errorOutput: Data(), exitCode: Int(exit) ?? -1)
    }
}

/// Replays one recorded gpg run for every crypto call, interpreted by the core exactly as the Libmacgpg backend does
final class FixtureBackend: PGPBackend {
    enum Call: Equatable {
        case decrypt(Data)
        case verify(signature: Data, signedData: Data)
        case verifyClearSigned(Data)
    }

    let run: GPGRun
    let calls = Mutex<[Call]>([])

    init(run: GPGRun) {
        self.run = run
    }

    convenience init(fixture name: String) throws {
        self.init(run: try Fixture.run(name))
    }

    var recordedCalls: [Call] { calls.withLock { $0 } }

    func decrypt(_ data: Data) throws -> PGPResult {
        calls.withLock { $0.append(.decrypt(data)) }
        return try run.decrypted()
    }

    func verify(signature: Data, signedData: Data) throws -> [Signature] {
        calls.withLock { $0.append(.verify(signature: signature, signedData: signedData)) }
        return try run.verified()
    }

    func verifyClearSigned(_ data: Data) throws -> PGPResult {
        calls.withLock { $0.append(.verifyClearSigned(data)) }
        return try run.clearSignedVerified()
    }

    func sign(_ data: Data, with key: PGPKey) throws -> DetachedSignature {
        throw PGPError.signingFailed("Not recorded")
    }

    func encrypt(_ data: Data, to recipients: [PGPKey], signedBy signer: PGPKey?) throws -> Data {
        throw PGPError.encryptionFailed("Not recorded")
    }

    func signingKey(for email: String) -> PGPKey? { nil }
    func encryptionKey(for email: String) -> PGPKey? { nil }
}

/// A pretend crypto engine with recognisable output. It remembers what it signed and encrypted, so messages it
/// encoded can be decoded again, and a signature only verifies against the exact bytes that were signed.
final class StubBackend: PGPBackend {
    struct Encryption: Equatable {
        let plaintext: Data
        let recipients: [PGPKey]
        let signer: PGPKey?
    }

    static let signature = Data("-----BEGIN PGP SIGNATURE-----\nFAKE-SIGNATURE\n-----END PGP SIGNATURE-----\n".utf8)

    let signingKeys: [String: String]
    let encryptionKeys: [String: String]
    let hashAlgorithm: HashAlgorithm
    private let state = Mutex<(signed: [Data], encrypted: [Encryption])>(([], []))

    init(signingKeys: [String: String] = [:], encryptionKeys: [String: String] = [:], hashAlgorithm: HashAlgorithm = HashAlgorithm(rawValue: 8)) {
        self.signingKeys = signingKeys
        self.encryptionKeys = encryptionKeys
        self.hashAlgorithm = hashAlgorithm
    }

    var signed: [Data] { state.withLock { $0.signed } }
    var encrypted: [Encryption] { state.withLock { $0.encrypted } }

    static func goodSignature(_ key: PGPKey) -> Signature {
        Signature(status: .good, signerName: "Stub", signerEmail: "stub@example.invalid", fingerprint: key.fingerprint)
    }

    func decrypt(_ data: Data) throws -> PGPResult {
        let text = String(decoding: data, as: UTF8.self)
        let encryptions = encrypted
        guard let index = encryptions.indices.first(where: { text.contains("FAKE-CIPHERTEXT-\($0)\r\n") }) else {
            throw PGPError.decryptionFailed("gpg: decryption failed: No secret key")
        }
        let encryption = encryptions[index]
        return PGPResult(data: encryption.plaintext, signatures: encryption.signer.map { [Self.goodSignature($0)] } ?? [])
    }

    func verify(signature: Data, signedData: Data) throws -> [Signature] {
        let good = signed.contains(signedData)
        return [Signature(status: good ? .good : .bad, signerName: "Stub", signerEmail: "stub@example.invalid")]
    }

    func verifyClearSigned(_ data: Data) throws -> PGPResult {
        throw PGPError.verificationFailed("Not supported")
    }

    func sign(_ data: Data, with key: PGPKey) throws -> DetachedSignature {
        state.withLock { $0.signed.append(data) }
        return DetachedSignature(armored: Self.signature, hashAlgorithm: hashAlgorithm)
    }

    func encrypt(_ data: Data, to recipients: [PGPKey], signedBy signer: PGPKey?) throws -> Data {
        let index = state.withLock { state in
            state.encrypted.append(Encryption(plaintext: data, recipients: recipients, signer: signer))
            return state.encrypted.count - 1
        }
        return Data("-----BEGIN PGP MESSAGE-----\nFAKE-CIPHERTEXT-\(index)\n-----END PGP MESSAGE-----\n".utf8)
    }

    func signingKey(for email: String) -> PGPKey? {
        signingKeys[email].map(PGPKey.init)
    }

    func encryptionKey(for email: String) -> PGPKey? {
        encryptionKeys[email].map(PGPKey.init)
    }
}

extension Data {
    /// True if any LF isn't preceded by CR
    var hasBareLineFeed: Bool {
        zip(self.dropLast(), self.dropFirst()).contains { $0.0 != 0x0D && $0.1 == 0x0A } || first == 0x0A
    }

    var utf8String: String { String(decoding: self, as: UTF8.self) }
}
