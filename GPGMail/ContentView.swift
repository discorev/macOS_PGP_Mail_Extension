//
//  ContentView.swift
//  GPGMail
//
//  Created by Oliver Hayman on 29/06/2021.
//

import AppKit
import SwiftUI

struct ContentView: View {
    @State private var isSuiteInstalled = GPGSuite.isInstalled

    var body: some View {
        SetupChecklist(isSuiteInstalled: isSuiteInstalled) {
            isSuiteInstalled = GPGSuite.isInstalled
        }
    }
}

/// GPG Suite on disk
enum GPGSuite {
    static var isInstalled: Bool {
        let files = FileManager.default
        return files.fileExists(atPath: "/usr/local/MacGPG2/bin/gpg") && files.fileExists(atPath: "/Library/Frameworks/Libmacgpg.framework")
    }
}

/// The setup steps. GPG Suite is the only one the app can check; the others say where to go.
struct SetupChecklist: View {
    let isSuiteInstalled: Bool
    let checkAgain: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Set up GPGMail")
                    .font(.title2.weight(.semibold))
                Text("GPGMail uses GPG Suite to sign, encrypt and check PGP mail in Apple Mail.")
                    .foregroundStyle(.secondary)
            }

            GroupBox {
                VStack(alignment: .leading, spacing: 12) {
                    suiteRow
                    Divider()
                    keysRow
                    Divider()
                    mailRow
                }
                .padding(8)
            }

            HStack {
                Spacer()
                Button("Check again", action: checkAgain)
            }
        }
        .padding(20)
        .frame(width: 420)
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private var suiteRow: some View {
        if isSuiteInstalled {
            CheckRow(symbol: "checkmark.circle.fill", colour: .green, title: "GPG Suite installed", detail: "Found in /usr/local/MacGPG2.")
        } else {
            CheckRow(symbol: "exclamationmark.circle.fill", colour: .orange, title: "GPG Suite not found", detail: "Install GPG Suite from [gpgtools.org](https://gpgtools.org), then check again.")
        }
    }

    @ViewBuilder private var keysRow: some View {
        if isSuiteInstalled {
            CheckRow(symbol: "key.fill", colour: .accentColor, title: "Your keys", detail: "Create or import your keys.") {
                Button("Open GPG Keychain") { Self.open("org.gpgtools.gpgkeychain") }
            }
        } else {
            CheckRow(symbol: "minus.circle.fill", colour: .secondary, title: "Your keys", detail: "Install GPG Suite first.")
        }
    }

    private var mailRow: some View {
        CheckRow(symbol: "puzzlepiece.extension.fill", colour: .accentColor, title: "Turn on GPGMail in Mail", detail: "In Mail › Settings › Extensions, turn on GPGMailExtention.") {
            Button("Open Mail") { Self.open("com.apple.mail") }
        }
    }

    private static func open(_ bundleIdentifier: String) {
        guard let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleIdentifier) else {
            return
        }
        NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
    }
}

private struct CheckRow<Accessory: View>: View {
    let symbol: String
    let colour: Color
    let title: String
    let detail: LocalizedStringKey
    @ViewBuilder var accessory: Accessory

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol)
                .foregroundStyle(colour)
                .frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            accessory
        }
    }
}

extension CheckRow where Accessory == EmptyView {
    init(symbol: String, colour: Color, title: String, detail: LocalizedStringKey) {
        self.init(symbol: symbol, colour: colour, title: title, detail: detail) { EmptyView() }
    }
}

#Preview {
    ContentView()
}
