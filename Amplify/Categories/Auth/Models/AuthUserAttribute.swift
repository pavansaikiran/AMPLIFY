//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public struct AuthUserAttribute {
    public let key: AuthUserAttributeKey
    public let value: String

    public init(_ key: AuthUserAttributeKey, value: String) {
        self.key = key
        self.value = value
    }
}

public enum AuthUserAttributeKey {

    case address
    case birthDate
    case email
    case familyName
    case gender
    case givenName
    case locale
    case middleName
    case name
    case nickname
    case phoneNumber
    case picture
    case preferredUsername
    case custom(String)
}
