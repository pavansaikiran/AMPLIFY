//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

// MARK: - Model

/// All persistent models should conform to the Model protocol.
public protocol Model: Codable {

    /// Alias of Model identifier (i.e. primary key)
    typealias Identifier = String

    /// A reference to the `ModelSchema` associated with this model.
    static var schema: ModelSchema { get }

    /// The name of the model, as registered in `ModelRegistry`.
    static var modelName: String { get }

    /// Convenience property to return the Type's `modelName`. Developers are strongly encouraged not to override the
    /// instance property, as an implementation that returns a different value for the instance property will cause
    /// undefined behavior.
    var modelName: String { get }

    /// The Model identifier (aka primary key)
    var id: Identifier { get }
}

extension Model {
    public static var modelName: String {
        return String(describing: self)
    }

    public var modelName: String {
        return type(of: self).modelName
    }
}

// MARK: - Model subscript

/// Implement dynamic access to properties of a `Model`.
///
/// ```swift
/// let id = model["id"]
/// ```
extension Model {

    public subscript(_ key: String) -> Any? {
        // TODO cache this for the instance?
        let mirror = Mirror(reflecting: self)
        let property = mirror.children.first { $0.label == key }
        return property == nil ? nil : property!.value
    }

    public subscript(_ key: CodingKey) -> Any? {
        return self[key.stringValue]
    }

}

// MARK: - Persistable

/// Types that conform to the `Persistable` protocol represent values that can be
/// persisted in a database.
///
/// Core Types that conform to this protocol:
/// - `Bool`
/// - `Date`
/// - `Double`
/// - `Int`
/// - `String`
public protocol Persistable {}

extension Bool: Persistable {}
extension Date: Persistable {}
extension Double: Persistable {}
extension Int: Persistable {}
extension String: Persistable {}

//public protocol PersistableEnum: Persistable {
//    func value() -> String
//}
//
//extension PersistableEnum where Self: RawRepresentable, Self.RawValue == String {
//    public func value() -> String {
//        return rawValue
//    }
//}

struct PersistableHelper {

    /// Polymorphic utility that allows two persistable references to be checked
    /// for equality regardless of their concrete type.
    ///
    /// - Note: Maintainers need to keep this utility updated when news types that conform
    /// to `Persistable` are added.
    ///
    /// - Parameters:
    ///   - lhs: a reference to a Persistable object
    ///   - rhs: another reference
    /// - Returns: `true` in case both values are equal or `false` otherwise
    public static func isEqual(_ lhs: Persistable?, _ rhs: Persistable?) -> Bool {
        if lhs == nil && rhs == nil {
            return true
        }
        switch (lhs, rhs) {
        case let (lhs, rhs) as (Bool, Bool):
            return lhs == rhs
        case let (lhs, rhs) as (Date, Date):
            return lhs == rhs
        case let (lhs, rhs) as (Double, Double):
            return lhs == rhs
        case let (lhs, rhs) as (Int, Int):
            return lhs == rhs
        case let (lhs, rhs) as (String, String):
            return lhs == rhs
        default:
            return false
        }
    }
}
