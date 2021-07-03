//
//  Errors.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

enum MessageSecurityError: Error {
    case couldNotDecrypt
    case signatureError
    var errorReason: String {
        switch self {
        case .signatureError:
            return "Error verifying signature."
        case .couldNotDecrypt:
            return "Could not decrypt message"
        }
    }
}
