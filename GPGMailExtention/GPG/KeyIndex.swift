//
//  KeyIndex.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 09/08/2021.
//

import Foundation
import Synchronization
import GPGCore

/// The GPG Suite keyring as a `KeyDirectory`.
///
/// Built once from the shared `GPGKeyManager`, and rebuilt on the next lookup after Libmacgpg reports the keys changed.
final class KeyIndex: Sendable {
    private let cached = Mutex<KeyDirectory?>(nil)

    init() {
        _ = NotificationCenter.default.addObserver(forName: .GPGKeyManagerKeysDidChange, object: nil, queue: nil) { [weak self] _ in
            self?.cached.withLock { $0 = nil }
        }
    }

    var directory: KeyDirectory {
        cached.withLock { cached in
            if let cached {
                return cached
            }
            let keys = GPGKeyManager.sharedInstance()?.allKeys as? Set<GPGKey> ?? []
            let directory = KeyDirectory(keys: keys.compactMap(Self.keyringKey))
            cached = directory
            return directory
        }
    }

    /// When the key that owns `fingerprint` (a primary key or one of its subkeys) expires, or nil if it never does
    func expirationDate(forFingerprint fingerprint: String) -> Date? {
        let keys = GPGKeyManager.sharedInstance()?.allKeys as? Set<GPGKey> ?? []
        let key = keys.first { key in
            key.fingerprint == fingerprint || (key.subkeys as? [GPGKey] ?? []).contains { $0.fingerprint == fingerprint }
        }
        return key?.expirationDate
    }

    private static func keyringKey(_ key: GPGKey) -> KeyringKey? {
        guard let fingerprint = key.fingerprint else {
            return nil
        }
        let emails = (key.userIDs as? [GPGUserID] ?? [])
            .filter { !isRevokedOrInvalid($0.validity) }
            .compactMap { $0.email as String? }
            .filter { !$0.isEmpty }
        let components = [key] + (key.subkeys as? [GPGKey] ?? [])
        return KeyringKey(
            fingerprint: fingerprint,
            emails: emails,
            hasSecretKey: key.secret,
            canAnySign: key.canAnySign,
            canAnyEncrypt: key.canAnyEncrypt,
            isUnusable: key.expired || key.revoked || key.disabled || key.invalid,
            created: key.creationDate,
            components: components.compactMap { component in
                component.fingerprint.map {
                    KeyringKey.Component(fingerprint: $0, canSign: component.canSign, canEncrypt: component.canEncrypt, isUnusable: component.expired || component.revoked || component.invalid)
                }
            }
        )
    }

    /// GPGValidity carries revoked and invalid as flags on top of the trust level
    private static func isRevokedOrInvalid(_ validity: GPGValidity) -> Bool {
        validity.rawValue & (GPGValidityRevoked.rawValue | GPGValidityInvalid.rawValue) != 0
    }
}
