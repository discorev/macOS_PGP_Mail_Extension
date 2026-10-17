//
//  MimeWriter.swift
//  GPGCore
//
//  Created by Oliver Hayman on 04/08/2021.
//

import Foundation

/// Writes a MIME entity: header fields, a blank line, then the body. Always CRLF.
public struct MimeWriter: Sendable {
    public var headers: Mime.Headers
    public var body: Data

    public init(headers: Mime.Headers = Mime.Headers(), body: Data = Data()) {
        self.headers = headers
        self.body = body
    }

    /// A multipart entity (RFC 2046 section 5.1). Any existing Content-Type in `headers` is replaced.
    /// - Parameters:
    ///   - subtype: e.g. `signed` or `encrypted`
    ///   - parameters: Content-Type parameters other than the boundary
    ///   - parts: Complete entities, written byte for byte between the delimiters
    public init(headers: Mime.Headers, multipart subtype: String, parameters: [(String, String)] = [], parts: [Data], boundary: String = MimeWriter.makeBoundary()) {
        var headers = headers
        headers.set("Content-Type", Mime.ContentType.value("multipart/\(subtype)", parameters + [("boundary", boundary)]))

        var body = Data()
        for part in parts {
            body.append(Data("--\(boundary)\r\n".utf8))
            body.append(part)
            // This line break belongs to the delimiter, not the part
            body.append(Mime.crlf)
        }
        body.append(Data("--\(boundary)--\r\n".utf8))
        self.init(headers: headers, body: body)
    }

    public static func makeBoundary() -> String {
        "GPGMail-\(UUID().uuidString)"
    }

    public var data: Data {
        var data = Data()
        for header in headers.fields {
            data.append(header.raw ?? Self.fold("\(header.name): \(header.value)"))
        }
        data.append(Mime.crlf)
        data.append(body)
        return data
    }

    /// Fold a generated field after its semicolons when it's longer than the 78 characters RFC 5322 recommends
    private static func fold(_ field: String) -> Data {
        guard field.count > 78 else {
            return Data("\(field)\r\n".utf8)
        }
        let folded = Mime.splitParameters(field).map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: ";\r\n\t")
        return Data("\(folded)\r\n".utf8)
    }
}
