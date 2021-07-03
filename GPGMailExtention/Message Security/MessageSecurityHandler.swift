//
//  MessageSecurityHandler.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit

class MessageSecurityHandler: NSObject, MEMessageSecurityHandler {
    static let shared = MessageSecurityHandler()
    
    override init() {
        super.init()
    }
    
    func keys() -> Set<GPGKey> {
        let keyManager = GPGKeyManager()
        return keyManager.allKeys as! Set<GPGKey>
    }

    // MARK: - Encoding Messages
    
    func encodingStatus(message: MEMessage) async -> MEOutgoingMessageEncodingStatus {
        var canSign = false, canEncrypt = false
        let keys = keys()
        let (publicKeys, secretKeys) = (keys.filter { $0.secret == false }, keys.filter { $0.secret })
        
        if let fromAddress = message.fromAddress.addressString?.lowercased() {
            // Loop through the secret keys to see if we have a suitable key for signing
            for key in secretKeys {
                for userId in key.userIDs as! [GPGUserID] {
                    if fromAddress == userId.email {
                        canSign = key.canSign
                        break
                    }
                }
            }
        }
        
        var failingEncryption: [MEEmailAddress] = []
        for toEmailAddress in message.toAddresses {
            var encryptable = false
            if let toAddress = toEmailAddress.addressString?.lowercased() {
                for userId in publicKeys.filter({ $0.canSign }).flatMap({ $0.userIDs as! [GPGUserID] }) {
                    if toAddress == userId.email {
                        encryptable = true
                        break
                    }
                }
            }
            if encryptable {
                canEncrypt = true
            } else {
                failingEncryption.append(toEmailAddress)
            }
        }
        if canEncrypt == false {
            failingEncryption.removeAll()
        }
        return MEOutgoingMessageEncodingStatus(canSign: canSign, canEncrypt: canEncrypt, securityError: nil, addressesFailingEncryption: failingEncryption)
    }
    
    func encode(_ message: MEMessage, shouldSign: Bool, shouldEncrypt: Bool, completionHandler: ((MEMessageEncodingResult) -> Void)) {
        // The result of the encoding operation. This object contains
        // the encoded message or an error to indicate what failed.
        let result: MEMessageEncodingResult
        
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
        result = MEMessageEncodingResult(encodedMessage: nil, signingError: nil, encryptionError: nil)
      
        // Call the completion handler with the result, or nil if
        // the extension didn't attempt to encode the message at all.
        completionHandler(result);
    }
          
    // MARK: - Decoding Messages
    
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
        return MessageSecurityViewController(nibName: "MessageSecurityViewController", bundle: Bundle.main
        )
    }
}
