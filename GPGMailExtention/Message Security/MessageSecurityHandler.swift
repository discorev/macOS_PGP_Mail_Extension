//
//  MessageSecurityHandler.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

@preconcurrency import MailKit
import GPGCore
import os


/// The MailKit shell: maps Mail's types to and from GPGCore, which does the actual work.
nonisolated final class MessageSecurityHandler: NSObject, MEMessageSecurityHandler, Sendable {
    static let shared = MessageSecurityHandler()

    private let backend = LibmacgpgBackend.shared

    // MARK: - Encoding Messages

    /// Check if a message being composed can be signed and or encrypted
    /// - Parameter message: Message to check
    /// - Returns:`MEOutgoingMessageEncodingStatus` showing if a message can be signed and or encrypted
    func encodingStatus(for message: MEMessage, composeContext: MEComposeContext) async -> MEOutgoingMessageEncodingStatus {
        let recipients = message.allRecipientAddresses
        let status = MessageEncoder(backend: backend).status(sender: Self.address(message.fromAddress), recipients: recipients.map(Self.address))
        let failing = recipients.filter { status.addressesFailingEncryption.contains(Self.address($0)) }
        return MEOutgoingMessageEncodingStatus(canSign: status.canSign, canEncrypt: status.canEncrypt, securityError: nil, addressesFailingEncryption: failing)
    }

    /// Perform encryption and signing of the message
    /// - Parameters:
    ///   - message: Message to sign or encrypt
    ///   - composeContext: Whether the user chose to sign and / or encrypt
    /// - Returns: The result of signing / encrypting
    func encode(_ message: MEMessage, composeContext: MEComposeContext) async -> MEMessageEncodingResult {
        guard let rawData = message.rawData else {
            return MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil)
        }

        let data = Self.canonical(rawData)
        let sign = composeContext.shouldSign && !MessageEncoder.isDraft(data)
        do {
            let encoded = try MessageEncoder(backend: backend).encode(data, sender: Self.address(message.fromAddress), recipients: message.allRecipientAddresses.map(Self.address), sign: sign, encrypt: composeContext.shouldEncrypt)
            let outgoing = MEEncodedOutgoingMessage(rawData: Self.forMail(encoded), isSigned: sign, isEncrypted: composeContext.shouldEncrypt)
            return MEMessageEncodingResult(encodedMessage: outgoing, signingError: nil, encryptionError: nil)
        } catch {
            Logger.gpgMail.error("Encoding failed: \(error.localizedDescription)")
            let isSigningError = (error as? PGPError)?.isSigningError ?? false
            return MEMessageEncodingResult(encodedMessage: nil, signingError: isSigningError ? error : nil, encryptionError: isSigningError ? nil : error)
        }
    }

    // MARK: - Decoding Messages

    /// Decrypt encoded message and check signature
    /// - Parameter data: RFC822 message
    /// - Returns:Decoded message or nil
    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let result: DecodedMessage?
        do {
            result = try MessageDecoder(backend: backend).decode(Self.canonical(data))
        } catch {
            Logger.gpgMail.error("Decoding failed: \(error.localizedDescription)")
            let securityInformation = MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: nil, encryptionError: error)
            return MEDecodedMessage(data: data, securityInformation: securityInformation, context: nil)
        }
        guard let result else {
            return nil
        }
        let statuses = result.signatures.map { "\($0.status)" }.joined(separator: ", ")
        Logger.gpgMail.notice("Decoded message: encrypted \(result.isEncrypted, privacy: .public), signatures [\(statuses, privacy: .public)], signing error: \(result.signingError?.localizedDescription ?? "none", privacy: .public)")

        let signers = result.signatures.map(signer(for:))
        let securityInformation = MEMessageSecurityInformation(signers: signers, isEncrypted: result.isEncrypted, signingError: result.signingError, encryptionError: nil)
        return MEDecodedMessage(data: Self.forMail(result.data), securityInformation: securityInformation, context: nil)
    }

    /// Line endings are adapted only here, at the MailKit edge. The core works in canonical CRLF.
    ///
    /// Mail 27 hands the extension CRLF, but shows "no content" for decoded messages returned with CRLF, so data
    /// going back to Mail is converted to bare LF (as the original 2021 code did). Mail restores CRLF when sending.
    private static func canonical(_ data: Data) -> Data {
        Mime.canonicalCRLF(data)
    }

    private static func forMail(_ data: Data) -> Data {
        var result = Data(capacity: data.count)
        var bytes = data.makeIterator()
        var pending = bytes.next()
        while let byte = pending {
            pending = bytes.next()
            if byte == 0x0D && pending == 0x0A { continue }
            result.append(byte)
        }
        return result
    }

    /// Mail's view of a signature. The core `Signature` rides along as JSON in the context for the details view.
    private func signer(for signature: Signature) -> MEMessageSigner {
        var emails = (signature.primaryKeyFingerprint ?? signature.fingerprint).map(backend.keys.directory.emails(forFingerprint:)) ?? []
        if emails.isEmpty, let email = signature.signerEmail {
            emails = [email]
        }
        let label = signature.status == .good ? signature.signerName ?? signature.signerEmail ?? "Unknown signer" : signature.status.summary
        return MEMessageSigner(emailAddresses: emails.map { MEEmailAddress(rawString: $0) }, signatureLabel: label, context: try? JSONEncoder().encode(signature))
    }

    private static func address(_ address: MEEmailAddress) -> String {
        address.addressString ?? address.rawString
    }

    // MARK: - Displaying Security Information

    /// The details panel for the signed badge. Each signer carries its core `Signature` as JSON.
    @MainActor func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        let decoder = JSONDecoder()
        let signatures = messageSigners.compactMap { try? decoder.decode(Signature.self, from: $0.context) }
        guard !signatures.isEmpty else {
            return nil
        }
        let details = signatures.map { signature in
            SignatureDetails(signature: signature, keyExpires: (signature.primaryKeyFingerprint ?? signature.fingerprint).flatMap(backend.keys.expirationDate(forFingerprint:)))
        }
        return MessageSecurityViewController(signatures: details)
    }

    /// Decoded messages don't carry a message context, so there's no banner view to show
    @MainActor func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        nil
    }

    @MainActor func primaryActionClicked(forMessageContext context: Data) async -> MEExtensionViewController? {
        nil
    }
}
