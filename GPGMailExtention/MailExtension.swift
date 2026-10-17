//
//  MailExtension.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit
import os

nonisolated final class MailExtension: NSObject, MEExtension {
    
    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        // Use a shared instance for all messages, since there's
        // no state associated with the security handler.
        return MessageSecurityHandler.shared
    }

}

extension Logger {
    /// The extension's log. GPGCore doesn't log; it returns errors for the extension to report.
    static let gpgMail = Logger(subsystem: "com.olliespage.GPGMail", category: "Extension")
}
