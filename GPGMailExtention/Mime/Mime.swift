//
//  Mime.swift
//  GPGMailExtention
//
//  Created by Oliver Hayman on 03/07/2021.
//

import Foundation

typealias MimeHeaders = [String: [String]]
let LINEFEED = "\n".data(using: .ascii)!

struct ContentType: CustomStringConvertible {
    let type: String
    let subtype: String
    let parameters: [String: String]
    
    public var raw: String {
        return "\(type)/\(subtype)"
    }
    
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
}

struct MimeMessage {
    let headers: MimeHeaders
    let contentType: ContentType
    let body: Data
    
    init(headers: MimeHeaders, body: Data) {
        self.headers = headers
        self.body = body
        
        if let contentType = headers.filter({ $0.key.lowercased() == "content-type" }).first?.value.first {
            var type: String = ""
            var subtype: String = ""
            var parameters: [String: String] = [:]
            // Split the content type up
            for part in contentType.split(separator: ";").map({ $0.trimmingCharacters(in: .whitespaces) }) {
                if part.contains("=") {
                    let param = part.split(separator: "=", maxSplits: 1)
                    let value = String(param[1].replacingOccurrences(of: "\"", with: ""))
                    parameters[String(param[0])] = value
                } else {
                    let typeData = part.split(separator: "/", maxSplits: 1)
                    let _type = typeData[0]
                    type = String(_type)
                    subtype = String(typeData.last!)
                }
            }
            self.contentType = ContentType(type: type, subtype: subtype, parameters: parameters)
            print(contentType)
            print(self.contentType)
        } else {
            self.contentType = ContentType(type: "", subtype: "", parameters: [:])
        }
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
            fullData.append(LINEFEED)
            fullData.append(body)
            return fullData
        }
    }
}

struct Mime {
    static func parse(data: Data) -> MimeMessage {
        let eml = String(data: data, encoding: .ascii)!
        var fieldName: String? = nil
        var fieldValue: String = ""
        var offset: Int = 0
        var headers = MimeHeaders()
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
                // We're now on a new field
                if let _ = headers[fieldName] {
                    headers[fieldName]?.append(fieldValue.trimmingCharacters(in: .whitespaces))
                } else {
                    headers[fieldName] = [fieldValue.trimmingCharacters(in: .whitespaces)]
                }
                fieldValue = ""
            }
            let headerParts = line.split(separator: ":", maxSplits: 1)
            fieldName = String(headerParts[0].trimmingCharacters(in: .whitespaces))
            if headerParts.count == 2 {
                fieldValue = String(headerParts[1].trimmingCharacters(in: .whitespaces))
            }
        }
        if let fieldName = fieldName {
            if let _ = headers[fieldName] {
                headers[fieldName]?.append(fieldValue.trimmingCharacters(in: .whitespaces))
            } else {
                headers[fieldName] = [fieldValue.trimmingCharacters(in: .whitespaces)]
            }
        }
        let mime = MimeMessage(headers: headers, body: data.advanced(by: offset))
        return mime
    }
    
    static func write(data: Data) -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString + ".eml")
        
        try? data.write(to: url)
        return url
    }
}
