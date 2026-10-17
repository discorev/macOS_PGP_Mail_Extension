//
//  MessageSecurityViewController.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 29/06/2021.
//

import MailKit
import SwiftUI

/// Hosts the signature details panel. Mail asks for a new one each time the signed badge is clicked.
final class MessageSecurityViewController: MEExtensionViewController {
    private let signatures: [SignatureDetails]

    init(signatures: [SignatureDetails]) {
        self.signatures = signatures
        super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func loadView() {
        let hostingView = NSHostingView(rootView: SignatureDetailsView(signatures: signatures))
        view = hostingView
        preferredContentSize = hostingView.fittingSize
    }
}
