//
//  MessageSecurityViewController.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit

class MessageSecurityViewController: MEExtensionViewController {
    
    static let sharedInstance = MessageSecurityViewController()
    
    var signers: [MEMessageSigner]?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        let decoder = JSONDecoder()
        // Do view setup here.
        if let signers = signers {
            for signer in signers {
                let signature = try? decoder.decode(ValidSignature.self, from: signer.context)
                print("signature: \(String(describing: signature))")
            }
        }
    }
    
    override var nibName: NSNib.Name? {
        return "MessageSecurityViewController"
    }

}

