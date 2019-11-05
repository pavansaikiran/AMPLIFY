//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

/// Adds JSON serialization behavior to all types that conform to the `Model` protocol.
extension Model where Self: Codable {

    /// De-serialize a JSON string into an instance of the concrete type that conforms
    /// to the `Model` protocol.
    ///
    /// - Parameter json: a valid JSON object as `String`
    /// - Returns: an instance of the concrete type conforming to `Model`
    /// - Throws: `DecodingError.dataCorrupted` in case data is not a valid JSON or any
    /// other decoding specific error that `JSONDecorder.decode()` might throw.
    public static func from(json: String) throws -> Self {
        let data = json.data(using: .utf8)!
        return try JSONDecoder().decode(Self.self, from: data)
    }

    /// De-serialize a `Dictionary` into an instance of the concrete type that conforms
    /// to the `Model` protocol.
    ///
    /// - Parameter dictionary: containing keys and values that match the target type
    /// - Returns: an instance of the concrete type conforming to `Model`
    /// - Throws: `DecodingError.dataCorrupted` in case data is not a valid JSON or any
    /// other decoding specific error that `JSONDecorder.decode()` might throw.
    public static func from(dictionary: [String: Any]) throws -> Self {
        let data = try JSONSerialization.data(withJSONObject: dictionary)
        return try JSONDecoder().decode(Self.self, from: data)
    }

    /// Converts the `Model` instance to a JSON object as `String`.
    /// - Returns: the JSON representation of the `Model`
    /// - seealso: https://developer.apple.com/documentation/foundation/jsonencoder/2895034-encode
    public func toJSON() throws -> String {
        let json = try JSONEncoder().encode(self)
        return String(data: json, encoding: .utf8)!
    }
}
