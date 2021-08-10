//
//  KeyManager.swift
//  KeyManager
//
//  Created by Oliver Hayman on 09/08/2021.
//

import Foundation
import MailKit

public class KeyManager {
    public static let sharedInstance = KeyManager()
    
    let gpgKeyManager: GPGKeyManager = GPGKeyManager.sharedInstance()
    
    func keys() -> Set<GPGKey> {
        return gpgKeyManager.allKeys as! Set<GPGKey>
    }
    
    private func normalise(address: MEEmailAddress) -> String? {
        return address.addressString?.lowercased()
    }
    
    func signingKey(for address: MEEmailAddress) -> GPGKey? {
        guard let normalizedAddress = normalise(address: address) else {
            return nil
        }
        
        // Loop through all secret keys and return the first that
        // matches the email provided
        for key in keys().filter({ $0.canSign }) {
            for userId in key.userIDs as! [GPGUserID] {
                if normalizedAddress == userId.email {
                    return key
                }
            }
        }
        return nil
    }
    
    func encryptionKey(for address: MEEmailAddress) -> GPGKey? {
        guard let normalizedAddress = normalise(address: address) else {
            return nil
        }
        
        for key in keys().filter({ $0.canEncrypt }) {
            for userId in key.userIDs as! [GPGUserID] {
                if normalizedAddress == userId.email {
                    return key
                }
            }
        }
        return nil
    }
    
    private init() {}
}
