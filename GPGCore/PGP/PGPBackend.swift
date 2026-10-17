//
//  PGPBackend.swift
//  GPGCore
//

import Foundation

/// A key the backend can sign or encrypt with, identified by fingerprint
public struct PGPKey: Sendable, Hashable {
    public let fingerprint: String

    public init(fingerprint: String) {
        self.fingerprint = fingerprint
    }
}

/// Output data together with the signatures found while producing it
public struct PGPResult: Sendable, Equatable {
    public let data: Data
    public let signatures: [Signature]

    public init(data: Data, signatures: [Signature]) {
        self.data = data
        self.signatures = signatures
    }
}

/// An ASCII-armoured detached signature and the hash it was made with
public struct DetachedSignature: Sendable, Equatable {
    public let armored: Data
    public let hashAlgorithm: HashAlgorithm

    public init(armored: Data, hashAlgorithm: HashAlgorithm) {
        self.armored = armored
        self.hashAlgorithm = hashAlgorithm
    }
}

/// The only way the core talks to crypto. Implementations throw `PGPError`.
public protocol PGPBackend: Sendable {
    /// Decrypt an OpenPGP message, verifying any signature inside it
    func decrypt(_ data: Data) throws -> PGPResult

    /// Verify a detached signature over `signedData`
    func verify(signature: Data, signedData: Data) throws -> [Signature]

    /// Verify a clear-signed message, returning the signed text
    func verifyClearSigned(_ data: Data) throws -> PGPResult

    /// Make an ASCII-armoured detached signature
    func sign(_ data: Data, with key: PGPKey) throws -> DetachedSignature

    /// Encrypt to every recipient key, signing in the same pass when `signer` is given. Returns ASCII armour.
    func encrypt(_ data: Data, to recipients: [PGPKey], signedBy signer: PGPKey?) throws -> Data

    /// A secret key that can sign for `email`
    func signingKey(for email: String) -> PGPKey?

    /// A public key that can encrypt to `email`
    func encryptionKey(for email: String) -> PGPKey?
}
