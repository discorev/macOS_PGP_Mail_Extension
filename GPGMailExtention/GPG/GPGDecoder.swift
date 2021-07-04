//
//  handler.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import MailKit
import Foundation

class GPGDecoder {
    static let sharedInstance = GPGDecoder()
    
    func keys() -> Set<GPGKey> {
        let keyManager = GPGKeyManager()
        return keyManager.allKeys as! Set<GPGKey>
    }
    
    /// Check if a mail message has parts that need decoding or signature validation
    /// - Parameter data: The EML message as data
    /// - Returns: True if this decoder can process the data further
    func shouldDecodeMessage(with data: Data) -> Bool {
        
        guard let rawEml = String(data: data, encoding: .utf8) else {
            return false
        }
        
        if let _ = rawEml.range(of: "-----BEGIN PGP MESSAGE-----") {
            return true
        }
        
        let mimeMessage = Mime.parse(data: data)
        if mimeMessage.contentType.type == "multipart" && mimeMessage.contentType.subtype == "encrypted" && mimeMessage.contentType.parameters["protocol"] == "application/pgp-encrypted" {
            return true
        }
        
        return false
    }
    
    /// Decode or validate the signature of an EML message
    /// - Parameter data: the EML message
    /// - Returns: A decrypted message
    func decodedMessage(from data: Data) -> MEDecodedMessage {
        // Declare the data needed for MEMessageSecurityInformation
        var signers: [MEMessageSigner] = []
        var isEncrypted: Bool = false
        var signingError: Error? = nil
        var decryptingError: Error? = nil
        
        let mimeMessage = Mime.parse(data: data)
//        let original = Mime.write(data: data)
//        print("Original: \(original.path)")
        let bodyString = String(data: mimeMessage.body, encoding: .utf8)
        if bodyString?.starts(with: "-----BEGIN PGP MESSAGE-----") ?? false {
            do {
                return try decryptBody(of: mimeMessage)
            } catch {
                decryptingError = error
            }
        }

        return MEDecodedMessage(data: data, securityInformation: MEMessageSecurityInformation(signers: signers, isEncrypted: isEncrypted, signingError: signingError, encryptionError: decryptingError))
    }
    
    func decryptBody(of mimeMessage: MimeMessage) throws -> MEDecodedMessage {
        var signers: [MEMessageSigner] = []
        var signingError: Error? = nil
        var decodedMessage: MEDecodedMessage? = nil

        // This block will prevent swift crashing the application if an NSException is thrown
        // from the Objective-c side fo things
        let exception = tryBlock {
            let gpgTask = GPGTask()
            gpgTask.nonBlocking = false
            // gpgTask.addArgument("--homedir")
            // gpgTask.addArgument(userHomeDirectory)
            gpgTask.addArgument("-d")
            gpgTask.setIn(mimeMessage.body)
            // gpgTask.addArgument(url.path)
            gpgTask.start() // We don't really care about the return code of GPG
            
            print("\(gpgTask.errText)")
            
            // Look for any bad signers
            if let signatureErrors = gpgTask.statusDict["ERRSIG"] as? Array<Array<String>> {
                for sigError in signatureErrors {
                    let errorDetail = Signaure(details: sigError, key: nil)
                    let signer = MEMessageSigner(emailAddresses: [], signatureLabel: errorDetail.description(), context: nil)
                    signers.append(signer)
                    if errorDetail.status == GPGErrorNoPublicKey {
                        signingError = MessageSecurityError.unknownSignature
                    } else {
                        signingError = MessageSecurityError.signatureError
                    }
                }
            }
            
            // And also for any good ones
            if let goodSigs = gpgTask.statusDict["GOODSIG"] as? Array<Array<String>> {
                let keys = self.keys()
                for sigDetails in goodSigs {
                    if let key = keys.first(where: { $0.keyID == sigDetails[0] }) {
                        let emails = (key.userIDs as! [GPGUserID]).map { MEEmailAddress(rawString: $0.email) }
                        let name = key.primaryUserID.name!
                        let signer = MEMessageSigner(emailAddresses: emails, signatureLabel: name, context: nil)
                        signers.append(signer)
                    }
                }
            }
            
            // Build a security info object with the signers information
            let securityInfo = MEMessageSecurityInformation(signers: signers, isEncrypted: true, signingError: signingError, encryptionError: nil)
            
            if let output = gpgTask.outText {
                let decrypted = MimeMessage(headers: mimeMessage.headers, body: output.data(using: .utf8)!)
//                let _final = Mime.write(data: decrypted.raw)
//                print("Final: \(_final.path)")
                decodedMessage = MEDecodedMessage(data: decrypted.raw, securityInformation: securityInfo)
            }
        }
        print("Exception \(exception)")
        guard let decodedMessage = decodedMessage else {
            throw MessageSecurityError.couldNotDecrypt
        }

        return decodedMessage
    }
}
