//
//  KeyIndex.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 09/08/2021.
//

import Foundation
import Synchronization

/// Email to key lookups over the GPG Suite keyring.
///
/// Built once from the shared `GPGKeyManager`, and rebuilt on the next lookup after Libmacgpg reports the keys changed.
final class KeyIndex: Sendable {
    private struct Snapshot: Sendable {
        /// Lower-cased email to fingerprint
        var signing: [String: String] = [:]
        var encryption: [String: String] = [:]
        /// Fingerprint of a key or any of its subkeys to the key's emails
        var emails: [String: [String]] = [:]
    }

    private let snapshot = Mutex<Snapshot?>(nil)

    init() {
        _ = NotificationCenter.default.addObserver(forName: .GPGKeyManagerKeysDidChange, object: nil, queue: nil) { [weak self] _ in
            self?.snapshot.withLock { $0 = nil }
        }
    }

    func signingKey(for email: String) -> String? {
        current().signing[email.lowercased()]
    }

    func encryptionKey(for email: String) -> String? {
        current().encryption[email.lowercased()]
    }

    /// Every email on the key with this (sub)key fingerprint
    func emails(forFingerprint fingerprint: String) -> [String] {
        current().emails[fingerprint.uppercased()] ?? []
    }

    private func current() -> Snapshot {
        snapshot.withLock { snapshot in
            if let snapshot {
                return snapshot
            }
            let built = Self.build()
            snapshot = built
            return built
        }
    }

    private static func build() -> Snapshot {
        let keys = GPGKeyManager.sharedInstance()?.allKeys as? Set<GPGKey> ?? []
        var snapshot = Snapshot()
        for key in keys {
            guard let fingerprint = key.fingerprint else {
                continue
            }
            let emails = (key.userIDs as? [GPGUserID] ?? []).compactMap { $0.email as String? }
            for email in emails {
                if key.canSign && snapshot.signing[email] == nil {
                    snapshot.signing[email] = fingerprint
                }
                if key.canEncrypt && snapshot.encryption[email] == nil {
                    snapshot.encryption[email] = fingerprint
                }
            }
            let fingerprints = key.allFingerprints as? Set<String> ?? [fingerprint]
            for fingerprint in fingerprints {
                snapshot.emails[fingerprint.uppercased()] = emails
            }
        }
        return snapshot
    }
}
