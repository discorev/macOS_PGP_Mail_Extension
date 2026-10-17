//
//  PGPError.swift
//  GPGCore
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

/// Errors from decoding and encoding PGP mail. Associated strings carry gpg's own explanation where there is one.
public enum PGPError: LocalizedError, Sendable, Equatable {
    /// The message claims to be PGP but doesn't have the expected structure
    case malformedMessage(String)
    case decryptionFailed(String)
    /// The signature couldn't be checked at all
    case verificationFailed(String)
    /// The signature was checked and isn't good
    case invalidSignature(Signature.Status)
    /// No usable secret key for the sender's address
    case noSigningKey(String)
    /// No usable public key for these addresses
    case noEncryptionKey([String])
    case signingFailed(String)
    case encryptionFailed(String)

    public var errorDescription: String? {
        switch self {
        case .malformedMessage(let detail):
            "The message isn't valid PGP/MIME: \(detail)"
        case .decryptionFailed(let detail):
            "Could not decrypt the message. \(detail)"
        case .verificationFailed(let detail):
            "Could not verify the signature. \(detail)"
        case .invalidSignature(let status):
            status.summary
        case .noSigningKey(let address):
            "No secret key found to sign as \(address)."
        case .noEncryptionKey(let addresses):
            "No public key found for \(addresses.joined(separator: ", "))."
        case .signingFailed(let detail):
            "Could not sign the message. \(detail)"
        case .encryptionFailed(let detail):
            "Could not encrypt the message. \(detail)"
        }
    }

    public var failureReason: String? {
        errorDescription
    }

    /// True when the error is about signing or verifying rather than encryption or decryption
    public var isSigningError: Bool {
        switch self {
        case .verificationFailed, .invalidSignature, .noSigningKey, .signingFailed: true
        case .malformedMessage, .decryptionFailed, .noEncryptionKey, .encryptionFailed: false
        }
    }
}
