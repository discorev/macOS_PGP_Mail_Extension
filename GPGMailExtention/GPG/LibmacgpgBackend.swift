//
//  LibmacgpgBackend.swift
//  GPGMailExtention
//

import Foundation
import GPGCore

/// `PGPBackend` over GPG Suite's Libmacgpg: runs gpg through `GPGTask` and finds keys in the shared `GPGKeyManager`.
///
/// gpg's output is interpreted by `GPGRun` in the core, from status lines rather than the exit code.
final class LibmacgpgBackend: PGPBackend {
    static let shared = LibmacgpgBackend()

    let keys = KeyIndex()

    func decrypt(_ data: Data) throws -> PGPResult {
        try run(["--decrypt"], input: data).decrypted()
    }

    func verify(signature: Data, signedData: Data) throws -> [Signature] {
        // gpg reads the signature from stdin and the signed data from a file
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        do {
            try signedData.write(to: url)
        } catch {
            throw PGPError.verificationFailed(error.localizedDescription)
        }
        defer { try? FileManager.default.removeItem(at: url) }
        return try run(["--verify", "-", url.path], input: signature).verified()
    }

    func verifyClearSigned(_ data: Data) throws -> PGPResult {
        // --decrypt on clear-signed input checks the signature and outputs the text
        try run(["--decrypt"], input: data).clearSignedVerified()
    }

    func sign(_ data: Data, with key: PGPKey) throws -> DetachedSignature {
        try run(["--armor", "--detach-sign", "--local-user", key.fingerprint], input: data).detachedSignature()
    }

    func encrypt(_ data: Data, to recipients: [PGPKey], signedBy signer: PGPKey?) throws -> Data {
        var arguments = ["--armor", "--encrypt"]
        for recipient in recipients {
            arguments += ["--recipient", recipient.fingerprint]
        }
        if let signer {
            arguments += ["--sign", "--local-user", signer.fingerprint]
        }
        return try run(arguments, input: data).encrypted(signed: signer != nil)
    }

    func signingKey(for email: String) -> PGPKey? {
        keys.directory.signingKey(for: email)
    }

    func encryptionKey(for email: String) -> PGPKey? {
        keys.directory.encryptionKey(for: email)
    }

    /// Run gpg. Libmacgpg adds `--status-fd` itself and collects the lines in `statusText`.
    private func run(_ arguments: [String], input: Data) -> GPGRun {
        let task = GPGTask()
        task.nonBlocking = false
        task.addArguments(arguments)
        task.setIn(input)

        // GPGTask reports some failures by raising an NSException, which Swift can't catch
        if let exception = tryBlock({ _ = task.start() }) {
            let reason = exception.reason ?? exception.name.rawValue
            return GPGRun(output: Data(), statusText: "", errorOutput: Data(reason.utf8), exitCode: -1)
        }
        return GPGRun(output: task.outData() ?? Data(), statusText: task.statusText ?? "", errorOutput: task.errData ?? Data(), exitCode: task.exitcode)
    }
}
