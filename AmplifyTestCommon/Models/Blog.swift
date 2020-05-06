//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// swiftlint:disable all
import Amplify
import Foundation

public struct Blog: Model {
    public let id: String
    public var content: String
    public var createdAt: Date
    public var owner: String?
    public var authorNotes: String?

    public init(id: String = UUID().uuidString,
                content: String,
                createdAt: Date,
                owner: String?,
                authorNotes: String?) {
        self.id = id
        self.content = content
        self.createdAt = createdAt
        self.owner = owner
        self.authorNotes = authorNotes
    }
}
