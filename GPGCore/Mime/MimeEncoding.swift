//
//  MimeEncoding.swift
//  GPGCore
//

import Foundation

public extension Mime {
    /// Convert every bare LF to CRLF, leaving existing CRLF pairs alone.
    ///
    /// The core works in canonical CRLF only (RFC 5322, RFC 3156). This accepts LF-only, CRLF and mixed input,
    /// and is idempotent, so it can never double-convert.
    static func canonicalCRLF(_ data: Data) -> Data {
        var result = Data()
        result.reserveCapacity(data.count + data.count / 32)
        var previous: UInt8? = nil
        for byte in data {
            if byte == lineFeed && previous != carriageReturn {
                result.append(carriageReturn)
            }
            result.append(byte)
            previous = byte
        }
        return result
    }

    /// Remove a base64 or quoted-printable Content-Transfer-Encoding. Other encodings are returned unchanged.
    static func decode(_ body: Data, transferEncoding: String?) -> Data {
        switch transferEncoding?.trimmingCharacters(in: .whitespaces).lowercased() {
        case "base64":
            return Data(base64Encoded: body, options: .ignoreUnknownCharacters) ?? body
        case "quoted-printable":
            return decodeQuotedPrintable(body)
        default:
            return body
        }
    }

    private static func decodeQuotedPrintable(_ body: Data) -> Data {
        let bytes = [UInt8](body)
        var result = Data()
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            guard byte == UInt8(ascii: "=") else {
                result.append(byte)
                index += 1
                continue
            }
            // Soft line break: "=" followed by CRLF or LF
            if index + 1 < bytes.count, bytes[index + 1] == lineFeed {
                index += 2
            } else if index + 2 < bytes.count, bytes[index + 1] == carriageReturn, bytes[index + 2] == lineFeed {
                index += 3
            } else if index + 2 < bytes.count, let high = hexValue(bytes[index + 1]), let low = hexValue(bytes[index + 2]) {
                result.append(high << 4 | low)
                index += 3
            } else {
                // Not a valid escape, keep it literally
                result.append(byte)
                index += 1
            }
        }
        return result
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
        case UInt8(ascii: "A")...UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
        case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
        default: nil
        }
    }
}
