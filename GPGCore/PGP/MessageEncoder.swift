//
//  MessageEncoder.swift
//  GPGCore
//
//  Created by Oliver Hayman on 08/08/2021.
//

import Foundation

/// Signs and encrypts outgoing mail as RFC 3156 PGP/MIME through a `PGPBackend`.
public struct MessageEncoder: Sendable {
    /// Whether a message being composed can be signed and/or encrypted
    public struct Status: Sendable, Equatable {
        public var canSign: Bool
        public var canEncrypt: Bool
        /// Recipients without a usable key. Only filled in when `canEncrypt` is true.
        public var addressesFailingEncryption: [String]
    }

    let backend: any PGPBackend

    public init(backend: any PGPBackend) {
        self.backend = backend
    }

    public func status(sender: String, recipients: [String]) -> Status {
        let failing = recipients.filter { backend.encryptionKey(for: $0) == nil }
        let canEncrypt = failing.count < recipients.count
        return Status(canSign: backend.signingKey(for: sender) != nil, canEncrypt: canEncrypt, addressesFailingEncryption: canEncrypt ? failing : [])
    }

    /// Sign and/or encrypt a message.
    ///
    /// Signing alone produces multipart/signed. Encrypting produces multipart/encrypted, signed inside the
    /// OpenPGP message in the same pass when `sign` is also set (RFC 3156 section 6.2).
    /// - Parameter message: An RFC 5322 message with CRLF line endings
    /// - Returns: The encoded message, CRLF
    /// - Throws: `PGPError`; `isSigningError` tells signing failures from encryption ones
    public func encode(_ message: Data, sender: String, recipients: [String], sign: Bool, encrypt: Bool) throws -> Data {
        guard sign || encrypt else {
            return message
        }

        let original = Mime.Part(from: message)
        // The Content-* fields describe the body, so they move inside with it; the rest stay on the outside
        let entity = MimeWriter(headers: Mime.Headers(original.headers.fields.filter(\.isContentField)), body: original.body).data
        var outer = Mime.Headers(original.headers.fields.filter { !$0.isContentField })
        if outer["MIME-Version"] == nil {
            outer.append("MIME-Version", "1.0")
        }

        var signer: PGPKey? = nil
        if sign {
            guard let key = backend.signingKey(for: sender) else {
                throw PGPError.noSigningKey(sender)
            }
            signer = key
        }

        if encrypt {
            let keys = recipients.map { ($0, backend.encryptionKey(for: $0)) }
            let missing = keys.filter { $0.1 == nil }.map(\.0)
            guard missing.isEmpty, !keys.isEmpty else {
                throw PGPError.noEncryptionKey(missing)
            }
            let ciphertext = try backend.encrypt(entity, to: keys.compactMap(\.1), signedBy: signer)
            return MimeWriter(headers: outer, multipart: "encrypted", parameters: [("protocol", "application/pgp-encrypted")], parts: [
                Self.versionPart,
                Self.part(["Content-Type": "application/octet-stream; name=\"openpgp-encrypted-message.asc\"",
                           "Content-Description": "OpenPGP encrypted message",
                           "Content-Disposition": "inline; filename=\"openpgp-encrypted-message.asc\"",
                           "Content-Transfer-Encoding": "7bit"], body: ciphertext),
            ]).data
        }

        guard let signer else {
            return message
        }
        let signature = try backend.sign(entity, with: signer)
        guard let micalg = signature.hashAlgorithm.micalg else {
            throw PGPError.signingFailed("Unknown hash algorithm \(signature.hashAlgorithm.rawValue).")
        }
        return MimeWriter(headers: outer, multipart: "signed", parameters: [("micalg", micalg), ("protocol", "application/pgp-signature")], parts: [
            entity,
            Self.part(["Content-Type": "application/pgp-signature; name=\"openpgp-digital-signature.asc\"",
                       "Content-Description": "OpenPGP digital signature",
                       "Content-Disposition": "attachment; filename=\"openpgp-digital-signature.asc\"",
                       "Content-Transfer-Encoding": "7bit"], body: signature.armored),
        ]).data
    }

    /// The control part of multipart/encrypted (RFC 3156 section 4)
    static let versionPart = part(["Content-Type": "application/pgp-encrypted", "Content-Description": "PGP/MIME version identification"], body: Data("Version: 1\r\n".utf8))

    private static func part(_ fields: KeyValuePairs<String, String>, body: Data) -> Data {
        MimeWriter(headers: Mime.Headers(fields.map { Mime.Header(name: $0.key, value: $0.value) }), body: Mime.canonicalCRLF(body)).data
    }
}
