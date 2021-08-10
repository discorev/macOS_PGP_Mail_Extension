//
//  Collection.swift
//  Collection
//
//  Created by Oliver Hayman on 09/08/2021.
//

import Foundation

public extension Collection {
    func unfoldSubSequences(limitedTo maxLength: Int) -> UnfoldSequence<SubSequence,Index> {
        sequence(state: startIndex) { start in
            guard start < self.endIndex else { return nil }
            let end = self.index(start, offsetBy: maxLength, limitedBy: self.endIndex) ?? self.endIndex
            defer { start = end }
            return self[start..<end]
        }
    }
    
    func distance(to index: Index) -> Int {
        return distance(from: startIndex, to: index)
    }
}
