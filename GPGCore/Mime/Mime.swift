//
//  Mime.swift
//  GPGCore
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

/// Parsing of RFC 5322 / MIME (RFC 2045, RFC 2046) entities.
///
/// The parser works on bytes and never traps on malformed input: anything it can't make sense of ends up in a body.
public enum Mime {
    static let carriageReturn: UInt8 = 0x0D
    static let lineFeed: UInt8 = 0x0A
    public static let crlf = Data([carriageReturn, lineFeed])

    /// A single header field.
    public struct Header: Sendable, Equatable {
        public let name: String
        /// The unfolded value with surrounding whitespace removed
        public let value: String
        /// The original bytes of a parsed field, including folding and the line ending, so it can be written back unchanged
        let raw: Data?

        public init(name: String, value: String) {
            self.name = name
            self.value = value
            raw = nil
        }

        /// Parse a field from its raw lines, e.g. `Subject: Hello\r\n`
        init?(raw: Data) {
            guard let colon = raw.firstIndex(of: UInt8(ascii: ":")) else {
                return nil
            }
            let unfolded = raw[raw.index(after: colon)...].filter { $0 != carriageReturn && $0 != lineFeed }
            name = Mime.string(from: raw[..<colon])
            value = Mime.string(from: unfolded).trimmingCharacters(in: .whitespaces)
            self.raw = Data(raw)
        }

        public func hasName(_ other: String) -> Bool {
            name.caseInsensitiveCompare(other) == .orderedSame
        }

        /// True for `Content-*` fields, which describe the entity rather than the message
        public var isContentField: Bool {
            name.lowercased().hasPrefix("content-")
        }
    }

    /// Ordered header fields with case-insensitive lookup.
    public struct Headers: Sendable, Equatable {
        public var fields: [Header]

        public init(_ fields: [Header] = []) {
            self.fields = fields
        }

        /// The first value for `name`
        public subscript(name: String) -> String? {
            fields.first { $0.hasName(name) }?.value
        }

        public func values(for name: String) -> [String] {
            fields.filter { $0.hasName(name) }.map(\.value)
        }

        public mutating func append(_ name: String, _ value: String) {
            fields.append(Header(name: name, value: value))
        }

        /// Replace every `name` field with a single one, kept in the position of the first
        public mutating func set(_ name: String, _ value: String) {
            let header = Header(name: name, value: value)
            guard let first = fields.firstIndex(where: { $0.hasName(name) }) else {
                fields.append(header)
                return
            }
            fields[first] = header
            fields = fields.enumerated().filter { $0.offset == first || !$0.element.hasName(name) }.map(\.element)
        }

        public mutating func remove(_ name: String) {
            fields.removeAll { $0.hasName(name) }
        }

        public var contentType: ContentType? {
            self["Content-Type"].map(ContentType.init)
        }

        public var contentDisposition: ContentDisposition? {
            self["Content-Disposition"].map(ContentDisposition.init)
        }
    }

    /// Content-Type header (RFC 2045)
    public struct ContentType: Sendable, Equatable {
        /// Lower-cased top-level type, e.g. `multipart`
        public let type: String
        /// Lower-cased subtype, e.g. `signed`
        public let subtype: String
        /// Parameters with lower-case keys
        public let parameters: [String: String]

        public init(_ value: String) {
            let fields = Mime.splitParameters(value)
            let mediaType = (fields.first ?? "").split(separator: "/", maxSplits: 1)
            type = mediaType.first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            subtype = mediaType.count == 2 ? mediaType[1].trimmingCharacters(in: .whitespaces).lowercased() : ""
            parameters = Mime.parameters(from: fields.dropFirst())
        }

        public var isMultipart: Bool { type == "multipart" }
        public var charset: String? { parameters["charset"] }
        public var boundary: String? { parameters["boundary"] }

        /// Case-insensitive check of the media type, e.g. `is("application", "pgp-signature")`
        public func `is`(_ type: String, _ subtype: String) -> Bool {
            self.type == type.lowercased() && self.subtype == subtype.lowercased()
        }

        /// Build a header value such as `multipart/signed; protocol="application/pgp-signature"`
        public static func value(_ mediaType: String, _ parameters: [(String, String)] = []) -> String {
            parameters.reduce(mediaType) { value, parameter in
                let escaped = parameter.1.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
                return value + "; \(parameter.0)=\"\(escaped)\""
            }
        }
    }

    /// Content-Disposition header (RFC 2183)
    public struct ContentDisposition: Sendable, Equatable {
        /// Represents the types of Content-Disposition as defined in RFC 2183
        public enum DispositionType: Sendable {
            /// Indicates the content is intended to be displayed automatically upon display of the message
            case inline
            /// Indicates the content is separate from the main body of the mail message,
            /// and display should not be automatic, but contingent upon some further action of the user
            case attachment
            /// Represents any unknown type
            case unknown
        }

        /// Disposition type indicating how the content should be handled when displayed to the user
        public let type: DispositionType
        /// Parameters will be stored as key value pairs with lower-case keys
        public let parameters: [String: String]

        public init(_ value: String) {
            let fields = Mime.splitParameters(value)
            switch fields.first?.trimmingCharacters(in: .whitespaces).lowercased() {
            case "inline": type = .inline
            case "attachment": type = .attachment
            default: type = .unknown
            }
            parameters = Mime.parameters(from: fields.dropFirst())
        }

        /// Suggested name of the file
        public var filename: String? { parameters["filename"] }
    }

    /// A structure representing a single mime part
    public struct Part: Sendable {
        /// The exact bytes this part was parsed from
        public let raw: Data
        public let headers: Headers
        /// Everything after the blank line that ends the headers
        public let body: Data
        public let contentType: ContentType?

        public init(from data: Data) {
            let data = Data(data) // Re-base indices to zero
            let (fields, bodyStart) = Mime.parseHeaders(data)
            raw = data
            headers = Headers(fields)
            body = Data(data[bodyStart...])
            contentType = headers.contentType
        }

        public var boundary: String? {
            contentType?.isMultipart == true ? contentType?.boundary : nil
        }

        public var isMultipart: Bool { boundary != nil }

        /// The body with any base64 or quoted-printable transfer encoding removed
        public var decodedBody: Data {
            Mime.decode(body, transferEncoding: headers["Content-Transfer-Encoding"])
        }

        /// The child parts of a multipart body, empty for any other part.
        ///
        /// Each child's `raw` excludes the line break before the next delimiter, which RFC 2046 treats as part of the delimiter.
        /// For `multipart/signed` that makes `raw` exactly the signed bytes.
        public var parts: [Part] {
            guard let boundary else {
                return []
            }
            return Mime.split(body, boundary: boundary)
        }
    }

    // MARK: - Parsing helpers

    /// Header bytes as text: UTF-8 (RFC 6532), falling back to Latin-1, which accepts any bytes
    static func string(from bytes: Data) -> String {
        String(data: bytes, encoding: .utf8) ?? String(data: bytes, encoding: .isoLatin1) ?? ""
    }

    /// The index just after the next line feed, or the end of the data
    static func lineEnd(in data: Data, from index: Data.Index) -> Data.Index {
        data[index...].firstIndex(of: lineFeed).map { data.index(after: $0) } ?? data.endIndex
    }

    /// Split header fields from the body. When the data doesn't start with a header, it is all body.
    static func parseHeaders(_ data: Data) -> (fields: [Header], bodyStart: Data.Index) {
        var fields: [Header] = []
        var fieldStart: Data.Index? = nil
        var lineStart = data.startIndex

        func endField(at end: Data.Index) {
            if let start = fieldStart, let header = Header(raw: data[start..<end]) {
                fields.append(header)
            }
            fieldStart = nil
        }

        while lineStart < data.endIndex {
            let next = lineEnd(in: data, from: lineStart)
            let line = data[lineStart..<next].filter { $0 != carriageReturn && $0 != lineFeed }

            if line.isEmpty {
                endField(at: lineStart)
                return (fields, next)
            }
            if let first = line.first, first == 0x20 || first == 0x09, fieldStart != nil {
                lineStart = next
                continue
            }
            endField(at: lineStart)
            guard isFieldStart(line) else {
                // Not a header: whatever follows is body
                return (fields, fields.isEmpty ? data.startIndex : lineStart)
            }
            fieldStart = lineStart
            lineStart = next
        }
        endField(at: data.endIndex)
        return (fields, data.endIndex)
    }

    /// A field name is one or more printable ASCII characters other than a colon (RFC 5322 section 3.6.8)
    static func isFieldStart(_ line: Data) -> Bool {
        guard let colon = line.firstIndex(of: UInt8(ascii: ":")), colon > line.startIndex else {
            return false
        }
        return line[..<colon].allSatisfy { (33...126).contains($0) }
    }

    /// Split a body on `--boundary` delimiter lines (RFC 2046 section 5.1.1)
    static func split(_ body: Data, boundary: String) -> [Part] {
        let delimiter = Data("--\(boundary)".utf8)
        let dashes = Data("--".utf8)
        var parts: [Part] = []
        var contentStart: Data.Index? = nil
        var searchFrom = body.startIndex

        while let found = body.range(of: delimiter, in: searchFrom..<body.endIndex) {
            searchFrom = found.upperBound
            let next = lineEnd(in: body, from: found.upperBound)
            let isClose = body[found.upperBound..<next].starts(with: dashes)
            let padding = body[(isClose ? found.upperBound + 2 : found.upperBound)..<next]
            // A delimiter starts a line and is followed only by transport padding
            guard found.lowerBound == body.startIndex || body[found.lowerBound - 1] == lineFeed,
                  padding.allSatisfy({ [0x20, 0x09, carriageReturn, lineFeed].contains($0) }) else {
                continue
            }

            if let start = contentStart {
                parts.append(Part(from: body[start..<trimmingLineBreak(body, start: start, end: found.lowerBound)]))
            }
            if isClose {
                return parts
            }
            contentStart = next
            searchFrom = next
        }

        // Missing close delimiter: keep what there is of the last part
        if let start = contentStart, start < body.endIndex {
            parts.append(Part(from: body[start...]))
        }
        return parts
    }

    /// Move `end` back over one CRLF or LF, without passing `start`
    static func trimmingLineBreak(_ data: Data, start: Data.Index, end: Data.Index) -> Data.Index {
        var end = end
        if end > start, data[end - 1] == lineFeed {
            end -= 1
            if end > start, data[end - 1] == carriageReturn {
                end -= 1
            }
        }
        return end
    }

    /// Split a header value on semicolons that aren't inside a quoted string
    static func splitParameters(_ value: String) -> [Substring] {
        var fields: [Substring] = []
        var start = value.startIndex
        var inQuotes = false
        var escaped = false
        for index in value.indices {
            let character = value[index]
            if escaped {
                escaped = false
            } else if character == "\\" && inQuotes {
                escaped = true
            } else if character == "\"" {
                inQuotes.toggle()
            } else if character == ";" && !inQuotes {
                fields.append(value[start..<index])
                start = value.index(after: index)
            }
        }
        fields.append(value[start...])
        return fields
    }

    static func parameters(from fields: ArraySlice<Substring>) -> [String: String] {
        var parameters: [String: String] = [:]
        for field in fields {
            let pair = field.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else {
                continue
            }
            let key = pair[0].trimmingCharacters(in: .whitespaces).lowercased()
            var value = pair[1].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, value.hasPrefix("\""), value.hasSuffix("\"") {
                value = unquote(value.dropFirst().dropLast())
            }
            // Ensure neither the key nor value are empty
            guard !key.isEmpty, !value.isEmpty else {
                continue
            }
            parameters[key] = value
        }
        return parameters
    }

    private static func unquote(_ quoted: Substring) -> String {
        var result = ""
        var escaped = false
        for character in quoted {
            if character == "\\" && !escaped {
                escaped = true
                continue
            }
            escaped = false
            result.append(character)
        }
        return result
    }
}
