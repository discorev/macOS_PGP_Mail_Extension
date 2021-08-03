//
//  Signature.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

enum PublicKeyAlgorithm: Int, Codable {
    case RSA = 1
    case RSAEncryptOnly = 2
    case RSASignOnly = 3
    case ElgamalEncryptOnly = 16
    case DSA = 17
    case ECDHA = 18
    case ECDSA = 19
    case Elgamal = 20
    case DiffieHellman = 21
    case EdDSA = 22
}

enum HashAlgorithm: Int, Codable {
    case MD5 = 1
    case SHA1 = 2
    case RMD160 = 3
    case SHA256 = 8
    case SHA384 = 9
    case SHA512 = 10
    case SHA224 = 11
}

struct ValidSignature : Codable {
    let fingerprint: String
    let signatureCreated: Date
    let expiry: Date?
    let signatureVersion: Int
    let keyAlgorithm: PublicKeyAlgorithm
    let hashAlgorithm: HashAlgorithm
    let signatureClass: Int
    let primaryKeyFingerpring: String
    
    init(detail: [String]) {
        fingerprint = detail[0]
        signatureCreated = Date(timeIntervalSince1970: Double(detail[2])!)
        if detail[3] == "0" {
            expiry = nil
        } else {
            expiry = Date(timeIntervalSince1970: Double(detail[3])!)
        }
        signatureVersion = Int(detail[4])!
        keyAlgorithm = PublicKeyAlgorithm(rawValue: Int(detail[6])!)!
        hashAlgorithm = HashAlgorithm(rawValue: Int(detail[7])!)!
        signatureClass = Int(detail[8])!
        primaryKeyFingerpring = detail[9]
    }
}

//struct Signaure: Codable {
struct BadSignaure {
    let fingerprint: String
    let keyAlgorithm: PublicKeyAlgorithm
    let hashAlgorithm: HashAlgorithm
    let signatureClass: Int
    let signatureDate: Date
    let status: GPGErrorCode
    let rsaKeyID: String
    let key: GPGKey?
    
    init(details: [String], key: GPGKey?) {
        fingerprint = details[0]
        keyAlgorithm = PublicKeyAlgorithm(rawValue: Int(details[1])!)!
        hashAlgorithm = HashAlgorithm(rawValue: Int(details[2])!)!
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
        
        return "\(sigStatus)"
    }
}
