//
//  GPGSigner.swift
//  GPGSigner
//
//  Created by Oliver Hayman on 08/08/2021.
//

import Foundation
import MailKit

class GPGEncoder {
    public static func sign(message: MEMessage) throws -> Data? {
        guard let messageData = message.rawData else {
            return nil
        }
        
        guard let signingKey = KeyManager.sharedInstance.signingKey(for: message.fromAddress) else {
            throw SendMessageSecurityError.unknownSigner
        }
        
        // Handle the fact messageData is invalid:
        var messageString = String(data: messageData, encoding: .utf8)!
        messageString = messageString.replacingOccurrences(of: "\n", with: "\r\n")
        // Fix any doubled line endings
        messageString = messageString.replacingOccurrences(of: "\r\r", with: "\r")
        
        return try sign(rawData: messageString.data(using: .utf8)!, with: signingKey)
    }
    
    public static func sign(rawData: Data, with key: GPGKey) throws -> Data? {
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.addArgument("--armour")
        
        let mime = Mime.Part(from: rawData)
        let messagePart = MimeWriter()
        if let contentType = mime.contentType {
            _ = messagePart.add(header: "Content-Type", value: contentType.raw)
        }
        messagePart.set(body: mime.body)
        // let messageData = messagePart.raw.dropLast(2)

        if let keyId = key.keyID {
            gpgTask.addArgument("--local-user")
            gpgTask.addArgument(keyId)
        }
        gpgTask.addArgument("--detach-sign")
        gpgTask.setIn(messagePart.raw)
        
        let exception: NSException? = tryBlock {
            gpgTask.start()
        }
        
        if exception != nil {
            throw SendMessageSecurityError.signingFailed
        }
        
        print(gpgTask.exitcode)
        guard gpgTask.outStream.length() > 0 else {
            return nil
        }
        
        let signaturePart = MimeWriter()
        _ = signaturePart.add(header: "Content-Type", value: "application/pgp-signature; name=\"openpgp-digital-signature.asc\"")
        _ = signaturePart.add(header: "Content-Transfer-Encoding", value: "7Bit")
        signaturePart.set(body: gpgTask.outStream.readAllData())
        
        let signedMessage = MimeWriter()
        // Set the key headers from the original mime message
        signedMessage.headers = mime.headers
        signedMessage.add(part: messagePart)
        signedMessage.add(part: signaturePart)
        
        // Update the content type
        guard signedMessage.add(header: "Content-Type", value: "multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"\(signedMessage.boundary!)\"") else {
            return nil
        }
        return signedMessage.raw
    }

    public static func encrypt(rawData: Data, for addresses: [MEEmailAddress]) throws -> Data? {
        let gpgTask = GPGTask()
        gpgTask.nonBlocking = false
        gpgTask.addArgument("--encrypt")
        gpgTask.addArgument("--armour")
        
        let mime = Mime.Part(from: rawData)
        let messagePart = MimeWriter()
        if let contentType = mime.contentType {
            _ = messagePart.add(header: "Content-Type", value: contentType.raw)
        }
        messagePart.set(body: mime.body)
        
        for address in addresses {
            if let addressString = address.addressString {
                gpgTask.addArgument("-r")
                gpgTask.addArgument(addressString)
            }
        }
        gpgTask.setIn(messagePart.raw)
        
        let exception: NSException? = tryBlock {
            gpgTask.start()
        }
        
        if exception != nil {
            throw SendMessageSecurityError.signingFailed
        }
        
        print(gpgTask.exitcode)
        guard gpgTask.outStream.length() > 0 else {
            return nil
        }
        
        let versionPart = MimeWriter()
        _ = versionPart.add(header: "Content-Type", value: "application/pgp-encrypted")
        versionPart.set(body: "Version: 1\r\n".data(using: .utf8)!)
        
        let encryptedPart = MimeWriter()
        _ = encryptedPart.add(header: "Content-Type", value: "application/octet-stream")
        _ = encryptedPart.add(header: "Content-Disposition", value: "inline; filename=\"openpgp-encrypted-message.asc\"")
        _ = encryptedPart.add(header: "Content-Transfer-Encoding", value: "7Bit")
        encryptedPart.set(body: gpgTask.outStream.readAllData())
        
        let encryptedMessage = MimeWriter()
        // Set the key headers from the original mime message
        encryptedMessage.headers = mime.headers
        encryptedMessage.add(part: versionPart)
        encryptedMessage.add(part: encryptedPart)
        
        // Update the content type
        guard encryptedMessage.add(header: "Content-Type", value: "multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"\(encryptedMessage.boundary!)\"") else {
            return nil
        }
        return encryptedMessage.raw
    }
    
}
