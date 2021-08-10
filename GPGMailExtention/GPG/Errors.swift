//
//  Errors.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

enum MessageSecurityError: LocalizedError {
    case couldNotDecrypt
    case signatureError
    case unknownSignature
    case badSignature
    var errorDescription: String? {
        switch self {
        case .signatureError:
            return "Error verifying signature."
        case .couldNotDecrypt:
            return "Could not decrypt message"
        case .unknownSignature:
            return "Signed by unknown sender"
        case .badSignature:
            return "The signed data did not match the signature"
        }
    }
    
    var failureReason: String? {
        return errorDescription
    }
}

enum SendMessageSecurityError: LocalizedError {
    case unknownSigner
    case signingFailed
    case unsupported
    
    var errorDescription: String? {
        switch self {
            case .unknownSigner:
                return "No signing certificate found."
            case .unsupported:
                return "This feature is currently unsupported"
            case .signingFailed:
                return "Failed to sign an error occured whilst handling GPG"
        }
    }
}
