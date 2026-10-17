//
//  SignatureDetailsView.swift
//  GPGMailExtention
//

import AppKit
import SwiftUI
import GPGCore

/// One signature as shown in the details panel, with what the keyring adds to it
struct SignatureDetails {
    var signature: Signature
    /// When the signing key expires, from the keyring. Nil if it doesn't, or the key isn't there.
    var keyExpires: Date?
}

/// The panel Mail shows when you click the signed badge
struct SignatureDetailsView: View {
    let signatures: [SignatureDetails]

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if signatures.isEmpty {
                Text("GPGMail has no signature details for this message.")
                    .foregroundStyle(.secondary)
            }
            ForEach(signatures.indices, id: \.self) { index in
                if index > 0 {
                    Divider()
                }
                SignatureSection(details: signatures[index])
            }
        }
        .padding(16)
        .frame(width: 360, alignment: .leading)
        .fixedSize(horizontal: false, vertical: true)
    }
}

private struct SignatureSection: View {
    let details: SignatureDetails

    private var signature: Signature { details.signature }
    private var description: SignatureDescription { SignatureDescription(signature) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            facts
            if let footnote {
                Text(footnote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: symbol)
                .font(.title2)
                .foregroundStyle(colour)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(description.title)
                    .font(.headline)
                if let subtitle = description.subtitle {
                    Text(subtitle)
                        .font(.subheadline.weight(.medium))
                }
                if let advice = description.advice {
                    Text(advice)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.top, 2)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var facts: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 6) {
            if let signer {
                row("Signed by") {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(signer.primary)
                        if let secondary = signer.secondary {
                            Text(secondary).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            if let fingerprint = signature.primaryKeyFingerprint ?? signature.fingerprint {
                row("Fingerprint") {
                    FingerprintText(fingerprint: fingerprint)
                }
            } else if let keyID {
                row("Key ID") {
                    Text(Fingerprint.grouped(keyID))
                        .monospaced()
                        .textSelection(.enabled)
                }
            }
            if let created = signature.created {
                row("Signed") {
                    Text(created.formatted(date: .abbreviated, time: .shortened))
                }
            }
            if showsValidity {
                row("Key") {
                    Text(signature.validity.plainDescription)
                }
            }
            if let keyExpires = details.keyExpires {
                row(keyExpires < .now ? "Key expired" : "Key expires") {
                    Text(keyExpires.formatted(date: .abbreviated, time: .omitted))
                }
            }
            if let expires = signature.expires {
                row(expires < .now ? "Signature expired" : "Signature expires") {
                    Text(expires.formatted(date: .abbreviated, time: .omitted))
                }
            }
        }
        .font(.callout)
    }

    private func row(_ label: String, @ViewBuilder value: () -> some View) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            value()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var signer: (primary: String, secondary: String?)? {
        switch (signature.signerName, signature.signerEmail) {
        case let (name?, email): (name, email)
        case let (nil, email?): (email, nil)
        case (nil, nil): nil
        }
    }

    /// gpg only gives a key ID, not a fingerprint, when it can't check the signature against a key
    private var keyID: String? {
        if case .unknownKey(let keyID) = signature.status {
            return keyID
        }
        return signature.keyID
    }

    /// Validity only means something once gpg has found the key and checked the signature against it
    private var showsValidity: Bool {
        switch signature.status {
        case .good, .expiredSignature, .expiredKey, .revokedKey: true
        case .bad, .unknownKey, .error: false
        }
    }

    private var footnote: String? {
        var parts = [signature.algorithmSummary].compactMap(\.self)
        if case .error(let code?) = signature.status {
            parts.append("gpg error \(code)")
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var symbol: String {
        switch description.tone {
        case .valid: "checkmark.seal.fill"
        case .caution: "exclamationmark.triangle.fill"
        case .invalid: "xmark.seal.fill"
        }
    }

    private var colour: Color {
        switch description.tone {
        case .valid: .green
        case .caution: .orange
        case .invalid: .red
        }
    }
}

/// The short fingerprint, with the full one in its tooltip and a button to copy it
private struct FingerprintText: View {
    let fingerprint: String

    var body: some View {
        HStack(spacing: 6) {
            Text(Fingerprint.short(fingerprint))
                .monospaced()
                .textSelection(.enabled)
                .help(Fingerprint.grouped(fingerprint))
            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(fingerprint, forType: .string)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy full fingerprint")
            .accessibilityLabel("Copy full fingerprint")
        }
    }
}
