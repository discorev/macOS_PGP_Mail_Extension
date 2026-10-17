//
//  GPGStatus.swift
//  GPGCore
//

import Foundation

/// What gpg reported on its status channel (`--status-fd`), parsed from `[GNUPG:] KEYWORD args` lines.
///
/// See doc/DETAILS in the GnuPG sources for the format. Unknown keywords and malformed lines are ignored.
public struct GPGStatus: Sendable, Equatable {
    /// One entry per signature, in the order gpg checked them
    public private(set) var signatures: [Signature] = []
    /// `DECRYPTION_OKAY` was seen
    public private(set) var decryptionOkay = false
    /// `DECRYPTION_FAILED` was seen
    public private(set) var decryptionFailed = false
    /// Key IDs from `NO_SECKEY`: the message was encrypted to these, but we don't have the secret key
    public private(set) var missingSecretKeys: [String] = []
    /// Hash used by a signature gpg just made (`SIG_CREATED`)
    public private(set) var createdSignatureHash: HashAlgorithm?
    /// `END_ENCRYPTION` was seen
    public private(set) var encryptionCompleted = false
    /// Where gpg failed, from `FAILURE <location> <code>`, e.g. `sign` or `encrypt`
    public private(set) var failureLocation: String?

    /// Decryption succeeded, whatever happened to any signature inside
    public var isDecrypted: Bool {
        decryptionOkay && !decryptionFailed
    }

    /// True when the current signature hasn't had a result line yet, so the next one belongs to it
    private var awaitingResult = false

    public init(parsing text: String) {
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard fields.count >= 2, fields[0] == "[GNUPG:]" else {
                continue
            }
            apply(keyword: fields[1], arguments: Array(fields.dropFirst(2)), line: String(line))
        }
    }

    private mutating func apply(keyword: String, arguments: [String], line: String) {
        switch keyword {
        case "NEWSIG":
            signatures.append(Signature(status: .error(code: nil)))
            awaitingResult = true
        case "GOODSIG":
            addResult(.good, arguments: arguments, line: line)
        case "BADSIG":
            addResult(.bad, arguments: arguments, line: line)
        case "EXPSIG":
            addResult(.expiredSignature, arguments: arguments, line: line)
        case "EXPKEYSIG":
            addResult(.expiredKey, arguments: arguments, line: line)
        case "REVKEYSIG":
            addResult(.revokedKey, arguments: arguments, line: line)
        case "ERRSIG":
            // ERRSIG <keyid> <pkalgo> <hashalgo> <sig_class> <time> <rc> [<fpr>]
            let keyID = arguments.first ?? ""
            let code = arguments.count > 5 ? Int(arguments[5]) : nil
            // rc 9 is "no public key"
            addResult(code == 9 ? .unknownKey(keyID: keyID) : .error(code: code), arguments: arguments, line: nil)
            updateCurrent { signature in
                signature.publicKeyAlgorithm = Self.int(arguments, 1).map(PublicKeyAlgorithm.init)
                signature.hashAlgorithm = Self.int(arguments, 2).map(HashAlgorithm.init)
                signature.created = Self.date(arguments, 4)
                if arguments.count > 6, arguments[6] != "-" {
                    signature.fingerprint = arguments[6]
                }
            }
        case "NO_PUBKEY":
            updateCurrent { signature in
                if case .error = signature.status, let keyID = arguments.first {
                    signature.status = .unknownKey(keyID: keyID)
                }
            }
        case "VALIDSIG":
            // VALIDSIG <fpr> <date> <timestamp> <expire> <version> <reserved> <pkalgo> <hashalgo> <class> [<primary fpr>]
            updateCurrent { signature in
                signature.fingerprint = arguments.first
                signature.created = Self.date(arguments, 2)
                signature.expires = Self.date(arguments, 3)
                signature.publicKeyAlgorithm = Self.int(arguments, 6).map(PublicKeyAlgorithm.init)
                signature.hashAlgorithm = Self.int(arguments, 7).map(HashAlgorithm.init)
                signature.primaryKeyFingerprint = arguments.count > 9 ? arguments[9] : nil
            }
        case "TRUST_UNDEFINED": setValidity(.undefined)
        case "TRUST_NEVER": setValidity(.never)
        case "TRUST_MARGINAL": setValidity(.marginal)
        case "TRUST_FULLY": setValidity(.full)
        case "TRUST_ULTIMATE": setValidity(.ultimate)
        case "DECRYPTION_OKAY":
            decryptionOkay = true
        case "DECRYPTION_FAILED":
            decryptionFailed = true
        case "NO_SECKEY":
            missingSecretKeys += arguments.prefix(1)
        case "SIG_CREATED":
            // SIG_CREATED <type> <pkalgo> <hashalgo> <class> <timestamp> <fpr>
            createdSignatureHash = Self.int(arguments, 2).map(HashAlgorithm.init)
        case "END_ENCRYPTION":
            encryptionCompleted = true
        case "FAILURE":
            failureLocation = arguments.first
        default:
            break
        }
    }

    /// Record the result line of a signature: `<KEYWORD> <keyid> <user id>`
    private mutating func addResult(_ status: Signature.Status, arguments: [String], line: String?) {
        if !awaitingResult {
            // Older gpg versions don't always send NEWSIG
            signatures.append(Signature(status: status))
        }
        awaitingResult = false
        updateCurrent { signature in
            signature.status = status
            signature.keyID = arguments.first
            if let line, let userID = Self.userID(from: line) {
                (signature.signerName, signature.signerEmail) = Self.nameAndEmail(from: userID)
            }
        }
    }

    private mutating func updateCurrent(_ update: (inout Signature) -> Void) {
        guard !signatures.isEmpty else {
            return
        }
        update(&signatures[signatures.count - 1])
    }

    private mutating func setValidity(_ validity: KeyValidity) {
        updateCurrent { $0.validity = validity }
    }

    // MARK: - Field helpers

    private static func int(_ arguments: [String], _ index: Int) -> Int? {
        index < arguments.count ? Int(arguments[index]) : nil
    }

    /// Status timestamps are seconds since the epoch; 0 means "none"
    private static func date(_ arguments: [String], _ index: Int) -> Date? {
        guard index < arguments.count, let seconds = Double(arguments[index]), seconds > 0 else {
            return nil
        }
        return Date(timeIntervalSince1970: seconds)
    }

    /// Everything after the key ID, with gpg's %XX escapes removed
    private static func userID(from line: String) -> String? {
        let fields = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
        guard fields.count == 4 else {
            return nil
        }
        let escaped = String(fields[3])
        return escaped.removingPercentEncoding ?? escaped
    }

    /// Split `Name (Comment) <email>` into its name and email
    static func nameAndEmail(from userID: String) -> (name: String?, email: String?) {
        var name = userID
        var email: String? = nil
        if let open = userID.lastIndex(of: "<"), let close = userID[open...].firstIndex(of: ">") {
            email = String(userID[userID.index(after: open)..<close])
            name = String(userID[..<open])
        }
        if let comment = name.firstIndex(of: "(") {
            name = String(name[..<comment])
        }
        name = name.trimmingCharacters(in: .whitespaces)
        return (name.isEmpty ? nil : name, email?.isEmpty == false ? email : nil)
    }
}
