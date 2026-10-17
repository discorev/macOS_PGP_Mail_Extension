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
class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()

    private let backend = LibmacgpgBackend.shared

    // MARK: - Encoding Messages

    /// Check if a message being composed can be signed and or encrypted
    /// - Parameter message: Message to check
    /// - Returns:`MEOutgoingMessageEncodingStatus` showing if a message can be signed and or encrypted
    nonisolated func encodingStatus(for message: MEMessage, composeContext: MEComposeContext) async -> MEOutgoingMessageEncodingStatus {
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
    nonisolated func encode(_ message: MEMessage, composeContext: MEComposeContext) async -> MEMessageEncodingResult {
        guard let rawData = message.rawData else {
            return MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil)
        }

        do {
            let encoded = try MessageEncoder(backend: backend).encode(Self.canonical(rawData), sender: Self.address(message.fromAddress), recipients: message.allRecipientAddresses.map(Self.address), sign: composeContext.shouldSign, encrypt: composeContext.shouldEncrypt)
            let outgoing = MEEncodedOutgoingMessage(rawData: encoded, isSigned: composeContext.shouldSign, isEncrypted: composeContext.shouldEncrypt)
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
    nonisolated func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
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

        let signers = result.signatures.map(signer(for:))
        let securityInformation = MEMessageSecurityInformation(signers: signers, isEncrypted: result.isEncrypted, signingError: result.signingError, encryptionError: nil)
        return MEDecodedMessage(data: result.data, securityInformation: securityInformation, context: nil)
    }

    /// The one place line endings are adapted at the MailKit edge: the core works in canonical CRLF and returns CRLF.
    ///
    /// What Mail 27 passes to `encode` and `decodedMessage` hasn't been captured, so this accepts LF-only, CRLF and
    /// mixed input and never double-converts. Verified by the end-to-end Mail test (plan step 6).
    private nonisolated static func canonical(_ data: Data) -> Data {
        Mime.canonicalCRLF(data)
    }

    /// Mail's view of a signature. The core `Signature` rides along as JSON in the context for the details view.
    private nonisolated func signer(for signature: Signature) -> MEMessageSigner {
        var emails = (signature.primaryKeyFingerprint ?? signature.fingerprint).map(backend.keys.directory.emails(forFingerprint:)) ?? []
        if emails.isEmpty, let email = signature.signerEmail {
            emails = [email]
        }
        let label = signature.status == .good ? signature.signerName ?? signature.signerEmail ?? "Unknown signer" : signature.status.summary
        return MEMessageSigner(emailAddresses: emails.map { MEEmailAddress(rawString: $0) }, signatureLabel: label, context: try? JSONEncoder().encode(signature))
    }

    private nonisolated static func address(_ address: MEEmailAddress) -> String {
        address.addressString ?? address.rawString
    }

    // MARK: - Displaying Security Information
    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        let controller = MessageSecurityViewController.sharedInstance
        controller.signers = messageSigners
        return controller
    }

    func extensionViewController(messageContext context: Data) -> MEExtensionViewController? {
        let controller = MessageSecurityViewController.sharedInstance
        // controller.signers = messageSigners
        return controller
    }

    func primaryActionClicked(forMessageContext context: Data) async -> MEExtensionViewController? {
        return nil
    }
}
