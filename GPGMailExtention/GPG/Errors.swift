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
    var errorDescription: String? {
        switch self {
        case .signatureError:
            return "Error verifying signature."
        case .couldNotDecrypt:
            return "Could not decrypt message"
        case .unknownSignature:
            return "Signed by unknown sender"
        }
    }
    
    var failureReason: String? {
        return errorDescription
    }
}
