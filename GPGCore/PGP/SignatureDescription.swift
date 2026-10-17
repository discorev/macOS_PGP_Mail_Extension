//
//  SignatureDescription.swift
//  GPGCore
//

import Foundation

/// The words used to explain a signature to the reader. Platform views only choose symbols and colours.
public struct SignatureDescription: Sendable, Equatable {
    /// How reassuring the result is, for the view to pick a symbol and colour
    public enum Tone: Sendable, Equatable {
        /// Good signature from a certified key
        case valid
        /// Good signature, but something about the key needs the reader's attention
        case caution
        /// The signature failed or couldn't be checked
        case invalid
    }

    public var tone: Tone
    public var title: String
    /// A short qualifier under the title, e.g. "This key isn't certified"
    public var subtitle: String?
    /// One or two sentences on what it means and what to do
    public var advice: String?

    public init(_ signature: Signature) {
        switch signature.status {
        case .good:
            self.init(goodSignatureWith: signature.validity)
        case .bad:
            self.init(tone: .invalid, title: "This signature doesn't match the message", advice: "The message may have been changed after it was signed.")
        case .unknownKey:
            self.init(tone: .caution, title: "Signed by a key you don't have", advice: "Import the sender's public key in GPG Keychain to check it.")
        case .expiredSignature:
            self.init(tone: .caution, title: "This signature has expired", advice: "The signature matches the message, but it's past the expiry date the sender gave it.")
        case .expiredKey:
            self.init(tone: .caution, title: "Signed with an expired key", advice: "The signature matches the message, but the sender's key has expired. If they've extended it, update the key in GPG Keychain.")
        case .revokedKey:
            self.init(tone: .invalid, title: "Signed with a revoked key", advice: "The sender has withdrawn this key, so don't rely on this signature. Ask them for their current key.")
        case .error:
            self.init(tone: .invalid, title: "This signature couldn't be checked", advice: "It may use an algorithm GPG doesn't support.")
        }
    }

    private init(goodSignatureWith validity: KeyValidity) {
        switch validity {
        case .full, .ultimate:
            self.init(tone: .valid, title: "Valid signature")
        case .unknown, .undefined, .marginal:
            self.init(tone: .caution, title: "Valid signature", subtitle: "This key isn't certified", advice: "The signature matches the key, but nobody you trust has confirmed whose key it is. Check the fingerprint with the sender, then certify the key in GPG Keychain.")
        case .never:
            self.init(tone: .invalid, title: "Valid signature", subtitle: "This key is marked as not valid", advice: "The signature matches the key, but your keyring says the key can't be trusted to belong to the sender.")
        }
    }

    private init(tone: Tone, title: String, subtitle: String? = nil, advice: String? = nil) {
        self.tone = tone
        self.title = title
        self.subtitle = subtitle
        self.advice = advice
    }
}

extension KeyValidity {
    /// How sure we are whose key it is, in plain words
    public var plainDescription: String {
        switch self {
        case .ultimate: "Your own key"
        case .full: "Certified"
        case .marginal: "Partly certified"
        case .unknown, .undefined: "Not certified"
        case .never: "Marked as not valid"
        }
    }
}

/// Fingerprint and key ID formatting
public enum Fingerprint {
    /// The last 16 hex digits in groups of four, e.g. `89AB CDEF 0123 4567`. This is also the long key ID.
    public static func short(_ fingerprint: String) -> String {
        grouped(String(hexDigits(fingerprint).suffix(16)))
    }

    /// All hex digits, upper case, in groups of four
    public static func grouped(_ fingerprint: String) -> String {
        let digits = hexDigits(fingerprint)
        return stride(from: 0, to: digits.count, by: 4)
            .map { offset in
                let start = digits.index(digits.startIndex, offsetBy: offset)
                return String(digits[start..<(digits.index(start, offsetBy: 4, limitedBy: digits.endIndex) ?? digits.endIndex)])
            }
            .joined(separator: " ")
    }

    private static func hexDigits(_ text: String) -> String {
        String(text.uppercased().filter(\.isHexDigit))
    }
}

extension Signature {
    /// The key's algorithms for a quiet secondary line, e.g. `RSA · SHA256`
    public var algorithmSummary: String? {
        let names = [publicKeyAlgorithm?.name, hashAlgorithm?.name].compactMap(\.self)
        return names.isEmpty ? nil : names.joined(separator: " · ")
    }
}
