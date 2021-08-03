//
//  MessageSecurityHandler.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()
    
    let keyManager: GPGKeyManager = GPGKeyManager.sharedInstance()
    
    func keys() -> Set<GPGKey> {
        return keyManager.allKeys as! Set<GPGKey>
    }
    
    func normalise(address: MEEmailAddress) -> String? {
        return address.addressString?.lowercased()
    }
    
    func signingKey(for address: MEEmailAddress) -> GPGKey? {
        guard let normalizedAddress = normalise(address: address) else {
            return nil
        }
        
        // Loop through all secret keys and return the first that
        // matches the email provided
        for key in keys().filter({ $0.canSign }) {
            for userId in key.userIDs as! [GPGUserID] {
                if normalizedAddress == userId.email {
                    return key
                }
            }
        }
        return nil
    }
    
    func encryptionKey(for address: MEEmailAddress) -> GPGKey? {
        guard let normalizedAddress = normalise(address: address) else {
            return nil
        }
        
        for key in keys().filter({ $0.canEncrypt }) {
            for userId in key.userIDs as! [GPGUserID] {
                if normalizedAddress == userId.email {
                    return key
                }
            }
        }
        return nil
    }

    // MARK: - Encoding Messages
    
    /// Check if a message being composed can be signed and or encrypted
    /// - Parameter message: Message to check
    /// - Returns:`MEOutgoingMessageEncodingStatus` showing if a message can be signed and or encrypted
    func encodingStatus(message: MEMessage) async -> MEOutgoingMessageEncodingStatus {
        var canSign = false, canEncrypt = false
        
        // Is there a valid signing key for the fromAddress?
        if let _ = signingKey(for: message.fromAddress) {
            canSign = true
        }
        
        var failingEncryption: [MEEmailAddress] = []
        for toAddress: MEEmailAddress in message.allRecipientAddresses {
            if let _ = encryptionKey(for: toAddress) {
                canEncrypt = true
            } else {
                failingEncryption.append(toAddress)
            }
        }
        
        // TODO: implement encryption
        canEncrypt = false
        
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
        // The result of the encoding operation. This object contains
        // the encoded message or an error to indicate what failed.
        let result: MEMessageEncodingResult
        
        var signingError: Error? = nil
        let encryptionError: Error? = nil
        
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.addArgument("--armour")
        
        // get the signing key
        if shouldSign {
            if let signKey = signingKey(for: message.fromAddress) {
                if let keyId = signKey.keyID {
                    gpgTask.addArgument("--local-user")
                    gpgTask.addArgument(keyId)
                }
                gpgTask.addArgument("--detach-sign")
            } else {
                signingError = MessageSecurityError.signatureError
            }
        }
        
//        if shouldEncrypt {
//            // We need to encrypt this for multiple keys?
//            if let _ = encryptionKey(for: toAddress)
//        }
        
//        let mimeMessage = MimeMessage(data: message.rawData!)
//        gpgTask.setIn(mimeMessage.body)
//        
//        // utilising the tryBlock ensures that NSException does not crash the app
//        let exception: NSException? = tryBlock {
//            gpgTask.start()
//        }
//        print(String(describing: exception))
//        print(String(describing: gpgTask.errText))
//        
//        if let outText = gpgTask.outText {
//            // build the output email based on this
//            print(outText)
//        }
//        

        
        // Add code here to sign and/or encrypt the message.
        //
        // If the encoding is successful, you create an instance
        // of MEEncodedOutgoingMessage that contains the encoded data and
        // indications whether the data is signed and/or encrypted.
        // For example:
        //
        // encodedMessage = MEEncodedOutgoingMessage(rawData:encodedData, isSigned:true, isEncrypted:true)
        //
        // Finally, create an MEMessageEncodingResult that includes the
        // MEEncodedOutgoingMessage or errors to indicate why the encoding
        // failed. If the message doesn't need to be encoded, pass nil,
        // otherwise pass an MEEncodedOutgoingMessage as shown above.
        result = MEMessageEncodingResult(encodedMessage: nil, signingError: signingError, encryptionError: encryptionError)
        
        return result
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
