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
        let mimeMessage = Mime.Part(from: data)
        
        // Check if the content type is a multi-part encrypted email
        if mimeMessage.contentType?.type == "multipart" && mimeMessage.contentType?.subtype == "encrypted" && mimeMessage.contentType?.parameters["protocol"] == "application/pgp-encrypted" {
            return true
        }
        
        // Check if the content type is a multi-part signed email
        if mimeMessage.contentType?.type == "multipart" && mimeMessage.contentType?.subtype == "signed" && mimeMessage.contentType?.parameters["protocol"] == "application/pgp-signature" {
            return true
        }
        
        // Now see if we can decode the body to a string
        guard let body = String(data: mimeMessage.body, encoding: .utf8) else {
            return false
        }
        
        // Check if there is an armoured encrypted message in the body
        if let _ = body.range(of: "-----BEGIN PGP MESSAGE-----"),
           let _ = body.range(of: "-----END PGP MESSAGE-----") {
            return true
        }
        
        // Check if there is the correct armour for a pgp signed message
        if let _ = body.range(of: "-----BEGIN PGP SIGNED MESSAGE-----"),
           let _ = body.range(of: "-----BEGIN PGP SIGNATURE-----"),
           let _ = body.range(of: "-----END PGP SIGNATURE-----") {
            return true
        }
        
        return false
    }
    
    /// Decode or validate the signature of an EML message
    /// - Parameter data: the EML message
    /// - Returns: A decrypted message
    func decodedMessage(from data: Data) -> MEDecodedMessage {
        // Declare the data needed for MEMessageSecurityInformation
        var signingError: Error? = nil
        var decryptingError: Error? = nil
        
        let mime = Mime.Part(from: data)
        
        if mime.isMultipart {
            do {
                if let result = try handleMultipart(mime) {
                    return result
                }
            }
            catch {
                decryptingError = error
            }
            
            return MEDecodedMessage(data: data, securityInformation: MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: signingError, encryptionError: decryptingError))
        }
        
        let bodyString = String(data: mime.body, encoding: .utf8)
        if bodyString?.starts(with: "-----BEGIN PGP MESSAGE-----") ?? false {
            do {
                let response = try decrypt(body: mime.body)
                let mimeResponse = MimeWriter()
                mimeResponse.headers = mime.headers
                mimeResponse.set(body: response.rawData!)
                // Ensure the content is sent formatted with \n for apple
                let appleHack = String(data: mimeResponse.rawData, encoding: .utf8)!.replacingOccurrences(of: "\r\n", with: "\n").data(using: .utf8)!
                
                return MEDecodedMessage(data: appleHack, securityInformation: response.securityInformation)
            } catch {
                decryptingError = error
            }
        }
        
        if let _ = bodyString?.range(of: "-----BEGIN PGP SIGNED MESSAGE-----"),
           let _ = bodyString?.range(of: "-----BEGIN PGP SIGNATURE-----"),
           let _ = bodyString?.range(of: "-----END PGP SIGNATURE-----") {
            do {
                if let result = try verify(body: mime.body) {
                    return result
                }
            }
            catch {
                signingError = error
            }
        }

        return MEDecodedMessage(data: data, securityInformation: MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: signingError, encryptionError: decryptingError))
    }
    
    func verify(body data: Data) throws -> MEDecodedMessage? {
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.addArgument("--verify")
        gpgTask.setIn(data)

        // This block will prevent swift crashing the application if an NSException is thrown
        // from the Objective-c side fo things
        let exception = tryBlock {
            gpgTask.start() // We don't really care about the return code of GPG
        }
        
        if let exception = exception {
            print("Exception: \(exception)")
            return nil
        }
        
        let securityInformation = getSignerData(forTask: gpgTask, wasEncrypted: false)
        
        return MEDecodedMessage(data: gpgTask.outData(), securityInformation: securityInformation)
    }
    
    func decrypt(body data: Data) throws -> MEDecodedMessage {
        var decodedMessage: MEDecodedMessage? = nil
        
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.addArgument("-d")
        gpgTask.setIn(data)

        // This block will prevent swift crashing the application if an NSException is thrown
        // from the Objective-c side fo things
        let exception = tryBlock {
            gpgTask.start() // We don't really care about the return code of GPG
        }
        print("Exception \(String(describing: exception))")
        print("\(String(describing: gpgTask.errText))")
        
        // Get the signer data from the task
        let securityInfo = getSignerData(forTask: gpgTask, wasEncrypted: true)
        
        if let output = gpgTask.outText {
            if let decrypted = output.data(using: .utf8) {
                decodedMessage = MEDecodedMessage(data: decrypted, securityInformation: securityInfo)
            }
        }
        
        guard let decodedMessage = decodedMessage else {
            throw MessageSecurityError.couldNotDecrypt
        }

        return decodedMessage
    }
    
    // To handle a multipart mime message: (1) decrypt the encrypted content
    // 2 check if the new content is multipart also, if so, change the multipart header over?
    func handleMultipart(_ mime: Mime.Part, wasEncrypted: Bool = false) throws -> MEDecodedMessage? {
        if mime.contentType?.subtype == "signed" && mime.contentType?.parameters["protocol"] == "application/pgp-signature",
           let algorithm = mime.contentType?.parameters["micalg"]  {
            return try verifyMultipart(mime, algorithm: algorithm, wasEncrypted: wasEncrypted)
        }
        
        guard var iterator: Mime.Part.Iterator = mime.iterator() else {
            return nil
        }
        
        var pgpEncrypted = false
        var result: MEDecodedMessage?
        while let part = iterator.next() {
            if part.contentType?.subtype == "pgp-encrypted" {
                // validate body
                if part.body == "Version: 1\n\n".data(using: .ascii)! {
                    pgpEncrypted = true
                }
                continue
            }
            
            if pgpEncrypted {
                let response = try decrypt(body: part.body)
                if let bodyData = response.rawData {
                    // Handle the fact that EMLs are CRLF
                    if let stringPart = String(data: bodyData, encoding: .utf8) {
                        let bodyText = stringPart.replacingOccurrences(of: "\r\n", with: "\n")
                    
                        result = MEDecodedMessage(data: bodyText.data(using: .utf8), securityInformation: response.securityInformation)
                    }
                    
                    let bodyMime = Mime.Part(from: bodyData)
                    if bodyMime.isMultipart {
                        if let nextLevel = try handleMultipart(bodyMime, wasEncrypted: true) {
                            result = nextLevel
                        }
                    }
                }
            }
        }
        return result
    }
    
    
    func verifyMultipart(_ mime: Mime.Part, algorithm: String, wasEncrypted: Bool) throws -> MEDecodedMessage? {
        var dataPart: Mime.Part?
        var dataUrl: URL? = nil
        var signatureData: Data?
        
        guard var iterator: Mime.Part.Iterator = mime.iterator() else {
            return nil
        }
        
        while let part = iterator.next() {
            if part.contentType?.subtype == "pgp-signature" {
                signatureData = Data(part.body)
                continue
            }
            
            guard dataUrl == nil else {
                continue
            }
            
            let rawData = part.raw
            let lastAddressableIndex = rawData.index(before: rawData.endIndex)
            
            // Walk backward from the end of the data to remove
            // Extra end of line characters
            var currentIndex = lastAddressableIndex
            while [0xD, 0xA].contains(rawData[currentIndex]) {
                currentIndex = rawData.index(before: currentIndex)
            }
            
            // currentIndex now points to the first non-end-of-line character
            // from the end of the string
            if currentIndex < lastAddressableIndex {
                currentIndex = rawData.index(after: currentIndex)
                if rawData[currentIndex] == 0xD && currentIndex < lastAddressableIndex {
                    currentIndex = rawData.index(after: currentIndex)
                }
            }
            
            dataUrl = Mime.write(data: rawData[...currentIndex])
            dataPart = part
        }
        
        guard let dataUrl = dataUrl,
              let signatureData = signatureData else {
                  // Clean up the data file to prevent littering
                  if let dataUrl = dataUrl {
                      try? FileManager.default.removeItem(at: dataUrl)
                  }
                  
                  return nil
              }
        
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.setIn(signatureData)
        gpgTask.addArgument("--verify")
        gpgTask.addArgument("-")
        gpgTask.addArgument(dataUrl.path)

        // This block will prevent swift crashing the application if an NSException is thrown
        // from the Objective-c side fo things
        let exception = tryBlock {
            gpgTask.start() // We don't really care about the return code of GPG
        }
        
        // Tidy up the dataUrl and supress any errors
        try? FileManager.default.removeItem(at: dataUrl)
        
        
        if let exception = exception {
            print("Exception: \(exception)")
            return nil
        }
        
        let securityInformation = getSignerData(forTask: gpgTask, wasEncrypted: wasEncrypted)
        if let dataPart = dataPart,
           let stringPart = String(data: dataPart.raw, encoding: .utf8) {
            
            let response = stringPart.replacingOccurrences(of: "\r\n", with: "\n")
            return MEDecodedMessage(data: response.data(using: .utf8), securityInformation: securityInformation)
        }
        return MEDecodedMessage(data: dataPart?.raw, securityInformation: securityInformation)
    }
    
    func getSignerData(forTask gpgTask: GPGTask, wasEncrypted: Bool) -> MEMessageSecurityInformation {
        var signers: [MEMessageSigner] = []
        var signingError: Error? = nil

        if let signatureErrors = gpgTask.statusDict["ERRSIG"] as? Array<Array<String>> {
            for sigError in signatureErrors {
                let errorDetail = BadSignaure(details: sigError, key: nil)
                let signer = MEMessageSigner(emailAddresses: [], signatureLabel: errorDetail.description(), context: nil)
                signers.append(signer)
                if errorDetail.status == GPGErrorNoPublicKey {
                    signingError = MessageSecurityError.unknownSignature
                } else {
                    signingError = MessageSecurityError.signatureError
                }
            }
        } else if let validSigs = gpgTask.statusDict["VALIDSIG"] as? Array<Array<String>> {
            let keys = self.keys()
            let encoder = JSONEncoder()
            for sig in validSigs {
                let sigDetail = ValidSignature(detail: sig)
                // check if the key exists in keys?
                if let key = keys.first(where: { $0.fingerprint == sigDetail.fingerprint }) {
                    let emails = (key.userIDs as! [GPGUserID]).map { MEEmailAddress(rawString: $0.email) }
                    let name = key.primaryUserID.name!
                    
                    let encoded = try? encoder.encode(sigDetail)
                    
                    let signer = MEMessageSigner(emailAddresses: emails, signatureLabel: name, context: encoded)
                    signers.append(signer)
                } else {
                    signingError = MessageSecurityError.unknownSignature
                }
            }
        } else if let badSigs = gpgTask.statusDict["BADSIG"] as? Array<Array<String>> {
            signingError = MessageSecurityError.badSignature
            for sig in badSigs {
                let name = "\(sig[1]) \(sig[2])"
                let email = MEEmailAddress(rawString: sig[3])
                signers.append(MEMessageSigner(emailAddresses: [email], signatureLabel: name, context: nil))
            }
        }
        
        return MEMessageSecurityInformation(signers: signers, isEncrypted: wasEncrypted, signingError: signingError, encryptionError: nil)
    }
}
