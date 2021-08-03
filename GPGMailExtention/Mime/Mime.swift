//
//  Mime.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

struct Mime {
    public typealias HeaderCollection = [String: [String]]
    public static let CARRAGE_RETURN: UInt8 = 0xD
    public static let LINEFEED: UInt8 = 0xA
    
    public struct Headers {
        public typealias HeaderParameters = [String: String]
        
        /// Content Disposition header
        public struct ContentDisposition {
            /// Represents the types of Content-Disposition as defined in RFC 2183
            public enum DispositionType {
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
            public let parameters: HeaderParameters
            
            /// Raw Content-Diposition value string
            public let raw: String
            
            /// Suggested name of the file
            public var filename: String? {
                return parameters["filename"]
            }
            
            /// Approximate size in bytes
            public var size: Int? {
                return Int(parameters["size"] ?? "")
            }
            
            /// Date on which the file was created
            public var creationDate: Date? {
                guard let dateString = parameters["creation-date"] else {
                    return nil
                }
                
                return try? Date(dateString, strategy: .iso8601)
            }
            
            /// Date on which the file was last modified
            public var modificationDate: Date? {
                guard let dateString = parameters["modification-date"] else {
                    return nil
                }
                
                return try? Date(dateString, strategy: .iso8601)
            }
            
            /// Date on which the file was last read
            public var readDate: Date? {
                guard let dateString = parameters["read-date"] else {
                    return nil
                }
                
                return try? Date(dateString, strategy: .iso8601)
            }
            
            public init(raw value: String) {
                raw = value
                let dispositionParams = value.split(separator: ";", omittingEmptySubsequences: true)
                // First set the type of disposition
                switch (dispositionParams[0].lowercased().trimmingCharacters(in: .whitespaces))
                {
                    case "inline":
                        type = .inline
                    break
                    case "attachment":
                        type = .attachment
                    break
                    default:
                        type = .unknown
                }
                
                parameters = processParameters(parameters: dispositionParams.dropFirst())
            }
        }
        
        /// Content Type header
        struct ContentType: CustomStringConvertible {
            let type: String
            let subtype: String
            let raw: String
            let parameters: HeaderParameters
            
            public var charset: String? {
                return parameters["charset"]
            }

            public var name: String? {
                return parameters["name"]
            }
            
            var description: String {
                var desc = raw
                for parameter in parameters {
                    desc += "; \(parameter.key)=\"\(parameter.value)\""
                }
                return desc
            }
            
            init(raw value: String) {
                raw = value
                let contentTypeParts = value.split(separator: ";", omittingEmptySubsequences: true)
                let typeData = contentTypeParts[0].split(separator: "/", maxSplits: 1, omittingEmptySubsequences: true)
                type = String(typeData[0])
                if typeData.count == 2 {
                    subtype = String(typeData[1])
                } else {
                    subtype = ""
                }
                
                parameters = processParameters(parameters: contentTypeParts.dropFirst())
            }
        }
        
        private static func processParameters<T>(parameters: ArraySlice<T>) -> HeaderParameters where T: StringProtocol {
            var params: [String: String] = [:]
            for parameter in parameters {
                let paramParts = parameter.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: true)
                // Ensure that there are two parts after the split
                guard paramParts.count == 2 else {
                    continue
                }
                
                let parameterKey = paramParts[0].lowercased().trimmingCharacters(in: .whitespaces)
                let parameterValue = paramParts[1].trimmingCharacters(in: .whitespaces)
                
                // Ensure neither the key nor value are empty
                guard parameterKey.isEmpty == false,
                      parameterValue.isEmpty == false else {
                    continue
                }
                
                params[parameterKey] = parameterValue.replacingOccurrences(of: "\"", with: "")
            }
            return params
        }
    }
    
    public struct Part {
        struct Iterator: IteratorProtocol {
            let data: Data
            let boundary: String
            let boundaryData: Data
            var position: Data.Index = 0
            
            init(data: Data, boundary: String) {
                self.boundary = boundary
                boundaryData = "\n--\(boundary)".data(using: .utf8)!
                        
                // Find the final boundary and use it to contrain the data
                if let finalBoundary = data.range(of: "--\(boundary)--".data(using: .utf8)!) {
                    var endPosition = finalBoundary.endIndex
                    // Try to include the final CRLF
                    while(data.count > endPosition + 1) {
                        endPosition = endPosition + 1
                        if data[endPosition] == LINEFEED {
                            break
                        }
                    }
                    self.data = Data(data[...endPosition])
                } else {
                    self.data = data
                }
                
                // If this fails, then the next() function will return nil
                if let first = data.range(of: boundaryData.dropFirst()) {
                    position = nextLine(from: first.endIndex)
                }
            }
            
            mutating func next() -> Mime.Part? {
                guard data.count > position else {
                    return nil
                }
                
                // find the next --boudnary in data
                if let nextRange = data[position...].range(of: boundaryData) {
                    let next = Mime.Part(from: data[position...nextRange.startIndex])
                    position = nextLine(from: nextRange.endIndex)
                    return next
                }
                return nil
            }
            
            private func nextLine(from index: Data.Index) -> Data.Index {
                if data.count >= (index + 2) && data[index] == CARRAGE_RETURN && data[index + 1] == LINEFEED {
                    return index + 2
                }
                return index + 1
            }
        }
        
        let raw: Data
        let headers: HeaderCollection
        let contentType: Headers.ContentType?
        let contentDisposition: Headers.ContentDisposition?
        private let bodyOffset: Data.Index
        var body: Data {
            get {
                return raw.advanced(by: bodyOffset)
            }
        }
        let isMultipart: Bool
        let boundary: String?
        
        func iterator() -> Mime.Part.Iterator? {
            guard isMultipart, let boundary = boundary else {
                return nil
            }

            return Mime.Part.Iterator(data: self.body, boundary: boundary)
        }
        
        init(from data: Data) {
            raw = Data(data)
            var headers: [String: [String]] = [:]
            let eml = String(data: data, encoding: .ascii)!.replacingOccurrences(of: "\r\n", with: "\n")
            var fieldName: String? = nil
            var fieldValue: String = ""
            var offset: Int = 0
            var contentDisposition: Headers.ContentDisposition? = nil
            var contentType: Headers.ContentType? = nil
            var isMultipart = false
            var boundary: String? = nil
            
            func updateOrCreateHeader(name: String, value: String) {
                if let _ = headers[name] {
                    headers[name]!.append(value)
                } else {
                    headers[name] = [value]
                }
                if name.lowercased() == "content-type" {
                    contentType = Headers.ContentType(raw: value)
                    if contentType!.type == "multipart" {
                        isMultipart = true
                        boundary = contentType!.parameters["boundary"]
                    }
                }
                if name.lowercased() == "content-disposition" {
                    contentDisposition = Headers.ContentDisposition(raw: value)
                }
            }
            
            for line in eml.components(separatedBy: .newlines) {
                offset += line.lengthOfBytes(using: .ascii) + 1
                if line.isEmpty {
                    break
                }
                if let fieldName = fieldName {
                    if line.prefix(1).rangeOfCharacter(from: .whitespaces) != nil {
                        fieldValue += " \(line.trimmingCharacters(in: .whitespaces))"
                        continue
                    }
                    
                    let value = fieldValue.trimmingCharacters(in: .whitespaces)
                    // We're now on a new field
                    updateOrCreateHeader(name: fieldName, value: value)
                    fieldValue = ""
                }
                let headerParts = line.split(separator: ":", maxSplits: 1)
                fieldName = String(headerParts[0].trimmingCharacters(in: .whitespaces))
                if headerParts.count == 2 {
                    fieldValue = String(headerParts[1].trimmingCharacters(in: .whitespaces))
                }
            }
            
            if let fieldName = fieldName {
                updateOrCreateHeader(name: fieldName, value: fieldValue.trimmingCharacters(in: .whitespaces))
            }
            
            self.headers = headers
            self.contentType = contentType
            self.contentDisposition = contentDisposition
            self.isMultipart = isMultipart
            self.boundary = boundary
            
            if headers.count > 0 {
                bodyOffset = offset
            } else {
                bodyOffset = 0
            }
        }
    }

    static func write(data: Data) -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString + ".eml")

        try? data.write(to: url)
        return url
    }
}


class MimeMessage {
    let headers: [String: [String]]
    let body: Data

    init(headers: Mime.HeaderCollection, body: Data) {
        self.headers = headers
        self.body = body
    }
    
    var raw: Data {
        get {
            var fullData = Data()
            for key in headers.keys {
                for headerValue in headers[key]! {
                    fullData.append("\(key): \(headerValue)\n".data(using: .ascii)!)
                }
            }
            // Ensure an empty line after the headers
            fullData.append(Mime.LINEFEED)
            fullData.append(body)
            return fullData
        }
    }
}
