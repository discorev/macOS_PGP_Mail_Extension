//
//  MessageDecoder.swift
//  GPGCore
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

/// A decrypted and/or verified message, ready to display
public struct DecodedMessage: Sendable {
    /// The rebuilt RFC 5322 message, CRLF
    public var data: Data
    public var isEncrypted: Bool
    public var signatures: [Signature]
    /// Set when a signature couldn't be checked at all
    public var verificationError: PGPError?

    /// The first signing problem, if any: a failed check or a signature that isn't good
    public var signingError: PGPError? {
        verificationError ?? signatures.first { $0.status != .good }.map { .invalidSignature($0.status) }
    }
}

/// Recognises PGP mail (RFC 3156 PGP/MIME and inline armour) and decodes it through a `PGPBackend`.
///
/// Input must be canonical CRLF; see `Mime.canonicalCRLF(_:)`.
public struct MessageDecoder: Sendable {
    public enum Kind: Sendable, Equatable {
        /// multipart/encrypted, RFC 3156 section 4
        case pgpMimeEncrypted
        /// multipart/signed, RFC 3156 section 5
        case pgpMimeSigned
        /// A text part containing an armoured `PGP MESSAGE`
        case inlineEncrypted
        /// A text part containing a clear-signed `PGP SIGNED MESSAGE`
        case inlineSigned
    }

    static let messageArmor = (begin: "-----BEGIN PGP MESSAGE-----", end: "-----END PGP MESSAGE-----")
    static let clearSignedArmor = (begin: "-----BEGIN PGP SIGNED MESSAGE-----", end: "-----END PGP SIGNATURE-----")

    let backend: any PGPBackend

    public init(backend: any PGPBackend) {
        self.backend = backend
    }

    /// What kind of PGP message this is, or nil if it isn't one
    public static func kind(of message: Data) -> Kind? {
        kind(of: Mime.Part(from: message))
    }

    static func kind(of part: Mime.Part) -> Kind? {
        if let contentType = part.contentType, contentType.isMultipart {
            let messageProtocol = contentType.parameters["protocol"]?.lowercased()
            if contentType.subtype == "encrypted" && messageProtocol == "application/pgp-encrypted" {
                return .pgpMimeEncrypted
            }
            if contentType.subtype == "signed" && messageProtocol == "application/pgp-signature" {
                return .pgpMimeSigned
            }
            return nil
        }

        // Inline PGP only lives in text parts; no Content-Type means text/plain
        guard part.contentType.map({ $0.type == "text" }) ?? true else {
            return nil
        }
        let body = part.decodedBody
        if armoredBlock(in: body, Self.messageArmor) != nil {
            return .inlineEncrypted
        }
        if armoredBlock(in: body, Self.clearSignedArmor) != nil {
            return .inlineSigned
        }
        return nil
    }

    /// Decrypt and/or verify a message.
    /// - Parameter message: An RFC 5322 message with CRLF line endings
    /// - Returns: The decoded message, or nil if the message isn't PGP
    /// - Throws: `PGPError` when the message can't be decrypted. Signature problems are reported in the result instead.
    public func decode(_ message: Data) throws -> DecodedMessage? {
        let part = Mime.Part(from: message)
        guard let kind = Self.kind(of: part) else {
            return nil
        }

        switch kind {
        case .pgpMimeEncrypted:
            let decrypted = try backend.decrypt(try Self.encryptedPayload(of: part))
            let entity = Mime.Part(from: Mime.canonicalCRLF(decrypted.data))
            var decoded = DecodedMessage(data: Data(), isEncrypted: true, signatures: decrypted.signatures)
            if Self.kind(of: entity) == .pgpMimeSigned {
                // Signed, then encrypted: surface the inner signature too
                let inner = verify(signed: entity)
                decoded.signatures += inner.signatures
                decoded.verificationError = inner.error
                decoded.data = Self.message(headers: part.headers, entity: inner.content)
            } else {
                decoded.data = Self.message(headers: part.headers, entity: entity)
            }
            return decoded

        case .pgpMimeSigned:
            let verified = verify(signed: part)
            return DecodedMessage(data: Self.message(headers: part.headers, entity: verified.content), isEncrypted: false, signatures: verified.signatures, verificationError: verified.error)

        case .inlineEncrypted:
            guard let armor = Self.armoredBlock(in: part.decodedBody, Self.messageArmor) else {
                return nil
            }
            let decrypted = try backend.decrypt(armor)
            return DecodedMessage(data: Self.textMessage(headers: part.headers, text: decrypted.data), isEncrypted: true, signatures: decrypted.signatures)

        case .inlineSigned:
            guard let armor = Self.armoredBlock(in: part.decodedBody, Self.clearSignedArmor) else {
                return nil
            }
            do {
                let verified = try backend.verifyClearSigned(armor)
                return DecodedMessage(data: Self.textMessage(headers: part.headers, text: verified.data), isEncrypted: false, signatures: verified.signatures)
            } catch {
                return DecodedMessage(data: message, isEncrypted: false, signatures: [], verificationError: Self.pgpError(error, otherwise: PGPError.verificationFailed))
            }
        }
    }

    /// Check a multipart/signed part, returning the content that was signed
    private func verify(signed part: Mime.Part) -> (content: Mime.Part, signatures: [Signature], error: PGPError?) {
        let parts = part.parts
        guard parts.count == 2, parts[1].contentType?.is("application", "pgp-signature") == true else {
            return (parts.first ?? part, [], .malformedMessage("multipart/signed needs a content part and an application/pgp-signature part"))
        }
        do {
            // `raw` stops before the line break that belongs to the delimiter, so it's exactly the signed bytes
            let signatures = try backend.verify(signature: parts[1].decodedBody, signedData: parts[0].raw)
            return (parts[0], signatures, nil)
        } catch {
            return (parts[0], [], Self.pgpError(error, otherwise: PGPError.verificationFailed))
        }
    }

    /// The ciphertext from a multipart/encrypted part
    static func encryptedPayload(of part: Mime.Part) throws -> Data {
        let parts = part.parts
        guard parts.count == 2, parts[0].contentType?.is("application", "pgp-encrypted") == true else {
            throw PGPError.malformedMessage("multipart/encrypted needs an application/pgp-encrypted part and an encrypted part")
        }
        // The control part says "Version: 1"; accept any line ending and trailing whitespace
        let version = String(decoding: parts[0].decodedBody, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        guard version == "Version: 1" else {
            throw PGPError.malformedMessage("unsupported PGP/MIME version \"\(version)\"")
        }
        return parts[1].decodedBody
    }

    /// The decoded message for a PGP/MIME message: the outer headers, minus those describing the
    /// encrypted or signed wrapper, followed by the inner entity
    static func message(headers outer: Mime.Headers, entity: Mime.Part) -> Data {
        let innerNames = Set(entity.headers.fields.map { $0.name.lowercased() })
        var headers = outer
        headers.fields.removeAll { $0.isContentField || innerNames.contains($0.name.lowercased()) }
        headers.fields += entity.headers.fields
        return MimeWriter(headers: headers, body: entity.body).data
    }

    /// The decoded message for inline PGP, whose plaintext is bare text with no MIME headers
    static func textMessage(headers outer: Mime.Headers, text: Data) -> Data {
        var headers = outer
        headers.remove("Content-Transfer-Encoding")
        headers.remove("Content-Length")
        headers.set("Content-Type", "text/plain; charset=UTF-8")
        headers.append("Content-Transfer-Encoding", "8bit")
        if headers["MIME-Version"] == nil {
            headers.append("MIME-Version", "1.0")
        }
        return MimeWriter(headers: headers, body: Mime.canonicalCRLF(text)).data
    }

    /// The armoured block from a BEGIN line to the end of its END line. BEGIN must start a line, so quoted
    /// replies such as `> -----BEGIN PGP MESSAGE-----` aren't picked up.
    static func armoredBlock(in body: Data, _ armor: (begin: String, end: String)) -> Data? {
        let begin = Data(armor.begin.utf8)
        var searchFrom = body.startIndex
        while let start = body.range(of: begin, in: searchFrom..<body.endIndex) {
            searchFrom = start.upperBound
            guard start.lowerBound == body.startIndex || body[start.lowerBound - 1] == Mime.lineFeed else {
                continue
            }
            guard let end = body.range(of: Data(armor.end.utf8), in: start.upperBound..<body.endIndex) else {
                return nil
            }
            return Data(body[start.lowerBound..<Mime.lineEnd(in: body, from: end.upperBound)])
        }
        return nil
    }

    private static func pgpError(_ error: any Error, otherwise wrap: (String) -> PGPError) -> PGPError {
        (error as? PGPError) ?? wrap(error.localizedDescription)
    }
}
