//
//  MessageSecurityHandler.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()

    // MARK: - Encoding Messages
    
    /// Check if a message being composed can be signed and or encrypted
    /// - Parameter message: Message to check
    /// - Returns:`MEOutgoingMessageEncodingStatus` showing if a message can be signed and or encrypted
    func encodingStatus(message: MEMessage) async -> MEOutgoingMessageEncodingStatus {
        var canSign = false, canEncrypt = false
        
        // Is there a valid signing key for the fromAddress?
        if let _ = KeyManager.sharedInstance.signingKey(for: message.fromAddress) {
            canSign = true
        }
        
        var failingEncryption: [MEEmailAddress] = []
        for toAddress: MEEmailAddress in message.allRecipientAddresses {
            if let _ = KeyManager.sharedInstance.encryptionKey(for: toAddress) {
                canEncrypt = true
            } else {
                failingEncryption.append(toAddress)
            }
        }
        
        // If canEncrypt is still false we don't have to worry about who'd fail encryption
        if canEncrypt == false {
            failingEncryption = []
        }
        
        return MEOutgoingMessageEncodingStatus(canSign: canSign, canEncrypt: canEncrypt, securityError: nil, addressesFailingEncryption: failingEncryption)
    }
    
    /// Perform encryption and signing of the message
    /// - Parameters:
    ///   - message: Message to sign or encrypt
    ///   - shouldSign: Indicates if the user selected / deselect the signing option
    ///   - shouldEncrypt: Indicates if the user selected / deselected the encryption option
    /// - Returns: The result of signing / encrypting
    func encode(_ message: MEMessage, shouldSign: Bool, shouldEncrypt: Bool) async -> MEMessageEncodingResult {
        var signingError: Error? = nil
        var encryptionError: Error? = nil
        var encodedMessage: Data? = nil
        
        // get the signing key
        if shouldSign {
            do {
                encodedMessage = try GPGEncoder.sign(message: message)
            } catch {
                signingError = error
            }
        }
        
        if shouldEncrypt {
            var data: Data
            if encodedMessage != nil {
                data = encodedMessage!
            } else {
                data = message.rawData!
            }
            
            do {
                encodedMessage = try GPGEncoder.encrypt(rawData: data, for: message.allRecipientAddresses)
            } catch {
                encryptionError = error
            }
        }
        
        guard let encodedMessage = encodedMessage else {
            return MEMessageEncodingResult(encodedMessage: nil, signingError: signingError, encryptionError: encryptionError)
        }
        
        let emlString = String(data: encodedMessage, encoding: .utf8)!
        
        let encoded = emlString.replacingOccurrences(of: "\r\n", with: "\n").data(using: .utf8)!
        
        let outgoingMessage = MEEncodedOutgoingMessage(rawData: encoded, isSigned: shouldSign && (signingError == nil), isEncrypted: shouldEncrypt && (encryptionError == nil))
        
        return MEMessageEncodingResult(encodedMessage: outgoingMessage, signingError: signingError, encryptionError: encryptionError)
    }
          
    // MARK: - Decoding Messages
    
    /// Decrypt encoded message and check signature
    /// - Parameter data: RFC822 message
    /// - Returns:Decoded message or nil
    func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let decoder = GPGDecoder.sharedInstance
        
        guard decoder.shouldDecodeMessage(with: data) else {
            return nil
        }
        
        return decoder.decodedMessage(from: data)
    }
 
    // MARK: - Displaying Security Information
    
    func extensionViewController(signers messageSigners: [MEMessageSigner]) -> MEExtensionViewController? {
        // Return a view controller that shows details about the encoded message.
        let controller = MessageSecurityViewController.sharedInstance
        controller.signers = messageSigners
        return controller
    }
}
