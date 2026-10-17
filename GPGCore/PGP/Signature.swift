//
//  Signature.swift
//  GPGCore
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

/// OpenPGP public key algorithm (RFC 4880 section 9.1). Unknown numbers are kept, never rejected.
public struct PublicKeyAlgorithm: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    /// The algorithm's name, or nil if the number isn't one we know
    public var name: String? {
        switch rawValue {
        case 1: "RSA"
        case 2: "RSA (encrypt only)"
        case 3: "RSA (sign only)"
        case 16: "Elgamal (encrypt only)"
        case 17: "DSA"
        case 18: "ECDH"
        case 19: "ECDSA"
        case 20: "Elgamal"
        case 21: "Diffie-Hellman"
        case 22: "EdDSA"
        default: nil
        }
    }
}

/// OpenPGP hash algorithm (RFC 4880 section 9.4). Unknown numbers are kept, never rejected.
public struct HashAlgorithm: RawRepresentable, Sendable, Hashable, Codable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    /// The algorithm's name, or nil if the number isn't one we know
    public var name: String? {
        switch rawValue {
        case 1: "MD5"
        case 2: "SHA1"
        case 3: "RIPEMD160"
        case 8: "SHA256"
        case 9: "SHA384"
        case 10: "SHA512"
        case 11: "SHA224"
        default: nil
        }
    }

    /// The `micalg` parameter for multipart/signed (RFC 3156 section 5), e.g. `pgp-sha256`
    public var micalg: String? {
        name.map { "pgp-\($0.lowercased())" }
    }
}

/// How far the signing key is trusted, from gpg's `TRUST_*` status lines
public enum KeyValidity: String, Sendable, Codable {
    case unknown, undefined, never, marginal, full, ultimate
}

/// The result of checking one signature
public struct Signature: Sendable, Equatable, Codable {
    public enum Status: Sendable, Equatable, Codable {
        /// The signature matches the data
        case good
        /// The data was changed after it was signed
        case bad
        /// The signing key isn't in the keyring, so the signature can't be checked
        case unknownKey(keyID: String)
        /// The signature is good, but it has expired
        case expiredSignature
        /// The signature is good, but the key that made it has expired
        case expiredKey
        /// The signature is good, but the key that made it has been revoked
        case revokedKey
        /// The signature couldn't be checked, e.g. an unsupported algorithm. `code` is gpg's error code.
        case error(code: Int?)
    }

    public var status: Status
    /// Long key ID or fingerprint gpg reported for the signing key
    public var keyID: String?
    public var signerName: String?
    public var signerEmail: String?
    /// Fingerprint of the key (or subkey) that made the signature
    public var fingerprint: String?
    public var primaryKeyFingerprint: String?
    public var created: Date?
    public var expires: Date?
    public var validity: KeyValidity
    public var publicKeyAlgorithm: PublicKeyAlgorithm?
    public var hashAlgorithm: HashAlgorithm?

    public init(status: Status, keyID: String? = nil, signerName: String? = nil, signerEmail: String? = nil, fingerprint: String? = nil, primaryKeyFingerprint: String? = nil, created: Date? = nil, expires: Date? = nil, validity: KeyValidity = .unknown, publicKeyAlgorithm: PublicKeyAlgorithm? = nil, hashAlgorithm: HashAlgorithm? = nil) {
        self.status = status
        self.keyID = keyID
        self.signerName = signerName
        self.signerEmail = signerEmail
        self.fingerprint = fingerprint
        self.primaryKeyFingerprint = primaryKeyFingerprint
        self.created = created
        self.expires = expires
        self.validity = validity
        self.publicKeyAlgorithm = publicKeyAlgorithm
        self.hashAlgorithm = hashAlgorithm
    }
}

extension Signature.Status {
    /// A short, human readable description of the status
    public var summary: String {
        switch self {
        case .good: "Signed"
        case .bad: "Bad signature: the message was changed after it was signed"
        case .unknownKey(let keyID): "Signed by an unknown key (\(keyID)). Import the sender's key to verify it."
        case .expiredSignature: "Signature expired"
        case .expiredKey: "Signed with an expired key"
        case .revokedKey: "Signed with a revoked key"
        case .error: "The signature could not be checked"
        }
    }
}
