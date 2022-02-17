//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Foundation

/// Represents a `create index` SQL statement. The table is created based on the `ModelSchema`
struct CreateIndexStatement: SQLStatement {

    let modelSchema: ModelSchema

    init(modelSchema: ModelSchema) {
        self.modelSchema = modelSchema
    }

    var stringValue: String {
        let tableName = modelSchema.name
        var statement = ""

        for index in modelSchema.indexes {
            if case let .index(fields, name) = index, let name = name {
                statement += """
                create index if not exists \"\(name)\" on \"\(tableName)\" (\(fields.map { "\"" + $0 + "\"" }.joined(separator: ", ")));
                """
            }
        }

        return statement
    }
}
