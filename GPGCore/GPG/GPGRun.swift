//
//  GPGRun.swift
//  GPGCore
//

import Foundation

/// The outcome of one gpg invocation, judged from its status lines rather than its exit code.
///
/// gpg exits 2 for "decrypted fine, but signed by a key you don't have", so the exit code alone can't tell success
/// from failure. A backend that runs gpg builds one of these and asks it for the result.
public struct GPGRun: Sendable {
    public let output: Data
    public let status: GPGStatus
    public let errorOutput: String
    public let exitCode: Int

    public init(output: Data, statusText: String, errorOutput: Data, exitCode: Int) {
        self.output = output
        self.status = GPGStatus(parsing: statusText)
        self.errorOutput = String(decoding: errorOutput, as: UTF8.self)
        self.exitCode = exitCode
    }

    /// gpg's own explanation, for error messages
    public var detail: String {
        let trimmed = errorOutput.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "gpg exited with status \(exitCode)." : trimmed
    }

    /// Result of `gpg --decrypt` on an encrypted message
    public func decrypted() throws -> PGPResult {
        guard status.isDecrypted else {
            throw PGPError.decryptionFailed(detail)
        }
        return PGPResult(data: output, signatures: status.signatures)
    }

    /// Result of `gpg --verify` with a detached signature
    public func verified() throws -> [Signature] {
        guard !status.signatures.isEmpty else {
            throw PGPError.verificationFailed(detail)
        }
        return status.signatures
    }

    /// Result of `gpg --decrypt` on a clear-signed message, which outputs the signed text
    public func clearSignedVerified() throws -> PGPResult {
        PGPResult(data: output, signatures: try verified())
    }

    /// Result of `gpg --armor --detach-sign`
    public func detachedSignature() throws -> DetachedSignature {
        guard let hash = status.createdSignatureHash, !output.isEmpty else {
            throw PGPError.signingFailed(detail)
        }
        return DetachedSignature(armored: output, hashAlgorithm: hash)
    }

    /// Result of `gpg --armor --encrypt`, optionally with `--sign`
    public func encrypted(signed: Bool) throws -> Data {
        let signedOkay = !signed || status.createdSignatureHash != nil
        guard status.encryptionCompleted, signedOkay, !output.isEmpty else {
            // gpg names the failing step; without that, a missing signature means signing went wrong
            let signingFailed = status.failureLocation.map { $0 == "sign" } ?? !signedOkay
            throw signingFailed ? PGPError.signingFailed(detail) : PGPError.encryptionFailed(detail)
        }
        return output
    }
}
