//
//  MimeWriter.swift
//  MimeWriter
//
//  Created by Oliver Hayman on 04/08/2021.
//

import Foundation

// This is a constant
let SINGLE_VALUE_HEADERS: Set = ["to", "cc", "bcc", "from", "subject", "mime-version"]

class MimeWriter {
    var headers: Mime.HeaderCollection = [:]
    var body: Data? = nil
    var parts: [Mime.Part] = []
    private(set) var boundary: String? = nil
    
    func add(header: String, value: String) -> Bool {
        let lowerHeader = header.lowercased()
        // Only ever allow a single value for some headers:
        if lowerHeader.starts(with: "content-") || SINGLE_VALUE_HEADERS.contains(lowerHeader) || headers[header] == nil {
            if lowerHeader == "content-type", let boundary = boundary {
                // Ensure the header is a multipart and includes `boundary`
                guard value.lowercased().starts(with: "multipart/") && value.contains("boundary=\"\(boundary)\"") else {
                    return false
                }
            }
            
            headers[header] = [value]
        } else {
            headers[header]!.append(value)
        }
        
        return true
    }
    
    func set(body: Data) {
        self.body = body
    }
    
    func add(part mimeContent: MimeWriter) {
        // Add the mimeContent as a full mime part
        parts.append(Mime.Part(from: mimeContent.raw))
        
        if boundary == nil {
            boundary = UUID().uuidString.lowercased()
            headers["Content-Type"] = ["multipart/mixed; boundary=\"\(boundary!)\""]
        }
    }
    
    var raw: Data {
        get {
            return rawData
        }
    }
    
    var rawData: Data {
        get {
            var finalData = Data()
            // Loop through the headers adding them to the data
            for (header, values) in headers {
                for value in values {
                    var valueString = "\(header): \(value)\r\n"
                    if valueString.count > 80 {
                        if valueString.contains(";") {
                            valueString = ""
                            for subValue in "\(header): \(value)".split(separator: ";") {
                                valueString += "\(subValue);\r\n\t"
                            }
                            let range = ..<valueString.index(valueString.endIndex, offsetBy: -3)
                            valueString = String(valueString[range])
                            valueString += "\r\n"
                        } else {
                            for part in "\(header): \(value)".unfoldSubSequences(limitedTo: 78) {
                                valueString += "\(part)\r\n\t"
                            }
                            let range = ..<valueString.index(valueString.endIndex, offsetBy: -1)
                            valueString = String(valueString[range])
                        }
                    }
                    finalData.append(contentsOf: valueString.data(using: .utf8)!)
                }
            }
            
            finalData.append(contentsOf: [Mime.CARRAGE_RETURN, Mime.LINEFEED])
            
            if let boundary = boundary {
                let boundaryData = "\r\n--\(boundary)\r\n".data(using: .utf8)!
                for part in parts {
                    finalData.append(boundaryData)
                    finalData.append(part.raw)
                }
                let finalBoundary = "\r\n--\(boundary)--\r\n".data(using: .utf8)!
                finalData.append(finalBoundary)
            } else if let body = body {
                finalData.append(body)
            }
            
            if finalData.last != Mime.LINEFEED {
                finalData.append(contentsOf: [Mime.CARRAGE_RETURN, Mime.LINEFEED])
            }
            
            return finalData
        }
    }
}
