//
//  KeyDirectory.swift
//  GPGCore
//

import Foundation

/// A key from the keyring, described in the terms key selection needs. Backends build these from their keyring.
public struct KeyringKey: Sendable {
    /// The primary key or one of its subkeys
    public struct Component: Sendable {
        public var fingerprint: String
        public var canSign: Bool
        public var canEncrypt: Bool
        /// Expired, revoked or otherwise invalid
        public var isUnusable: Bool

        public init(fingerprint: String, canSign: Bool, canEncrypt: Bool, isUnusable: Bool) {
            self.fingerprint = fingerprint
            self.canSign = canSign
            self.canEncrypt = canEncrypt
            self.isUnusable = isUnusable
        }
    }

    public var fingerprint: String
    public var emails: [String]
    public var hasSecretKey: Bool
    /// The key or any subkey has the capability. Modern keys sign with the primary key and encrypt with a subkey.
    public var canAnySign: Bool
    public var canAnyEncrypt: Bool
    /// The whole key is expired, revoked, disabled or invalid
    public var isUnusable: Bool
    public var created: Date?
    /// The primary key, then its subkeys
    public var components: [Component]

    public init(fingerprint: String, emails: [String], hasSecretKey: Bool, canAnySign: Bool, canAnyEncrypt: Bool, isUnusable: Bool, created: Date?, components: [Component]) {
        self.fingerprint = fingerprint
        self.emails = emails
        self.hasSecretKey = hasSecretKey
        self.canAnySign = canAnySign
        self.canAnyEncrypt = canAnyEncrypt
        self.isUnusable = isUnusable
        self.created = created
        self.components = components
    }

    /// A secret key with at least one live component that can sign
    var isUsableForSigning: Bool {
        hasSecretKey && canAnySign && !isUnusable && components.contains { $0.canSign && !$0.isUnusable }
    }

    /// A key with at least one live component that can encrypt
    var isUsableForEncryption: Bool {
        canAnyEncrypt && !isUnusable && components.contains { $0.canEncrypt && !$0.isUnusable }
    }
}

/// Email to key lookups. Emails match case-insensitively; when several keys match, the newest wins.
public struct KeyDirectory: Sendable {
    private var signing: [String: PGPKey] = [:]
    private var encryption: [String: PGPKey] = [:]
    /// Fingerprint of any component to the key's emails
    private var emails: [String: [String]] = [:]

    public init(keys: [KeyringKey]) {
        let newestFirst = keys.sorted {
            ($0.created ?? .distantPast, $0.fingerprint) > ($1.created ?? .distantPast, $1.fingerprint)
        }
        for key in newestFirst {
            let addresses = key.emails.map(Self.normalise)
            for address in addresses {
                if key.isUsableForSigning && signing[address] == nil {
                    signing[address] = PGPKey(fingerprint: key.fingerprint)
                }
                if key.isUsableForEncryption && encryption[address] == nil {
                    encryption[address] = PGPKey(fingerprint: key.fingerprint)
                }
            }
            for fingerprint in [key.fingerprint] + key.components.map(\.fingerprint) {
                emails[fingerprint.uppercased()] = key.emails
            }
        }
    }

    public func signingKey(for email: String) -> PGPKey? {
        signing[Self.normalise(email)]
    }

    public func encryptionKey(for email: String) -> PGPKey? {
        encryption[Self.normalise(email)]
    }

    /// Every email on the key that has a component with this fingerprint
    public func emails(forFingerprint fingerprint: String) -> [String] {
        emails[fingerprint.uppercased()] ?? []
    }

    static func normalise(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespaces).lowercased()
    }
}
