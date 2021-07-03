//
//  Signature.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

struct Signaure {
    let fingerprint: String
    let keyAlgorithm: GPGPublicKeyAlgorithm
    let hashAlgorithm: GPGHashAlgorithm
    let signatureClass: Int
    let signatureDate: Date
    let status: GPGErrorCode
    let rsaKeyID: String
    let key: GPGKey?
    
    init(details: [String], key: GPGKey?) {
        fingerprint = details[0]
        keyAlgorithm = GPGPublicKeyAlgorithm(rawValue: UInt32(details[1])!)
        hashAlgorithm = GPGHashAlgorithm(rawValue: Int(details[2])!)!
        signatureClass = Int(details[3])!
        signatureDate = Date(timeIntervalSince1970: Double(details[4])!)
        status = GPGErrorCode(rawValue: UInt32(details[5])!)
        rsaKeyID = details[6]
        self.key = key
    }
    
    func description() -> String {
        let sigStatus: String
        switch(status) {
            case GPGErrorNoError:
                sigStatus = "Signed"
            break;
            case GPGErrorSignatureExpired, GPGErrorKeyExpired:
                sigStatus = "Signature expired"
                break;
            case GPGErrorCertificateRevoked:
                sigStatus = "Signature revoked"
                break;
            case GPGErrorUnknownAlgorithm:
                sigStatus = "Unverifiable signature"
                break;
            case GPGErrorNoPublicKey:
                sigStatus = "Signed by stranger"
                break;
            case GPGErrorBadSignature:
                sigStatus = "Bad signature"
                break;
            default:
                sigStatus = "Signature error"
                break;
        }
        
        return "\(sigStatus) (\(fingerprint))"
    }
}
