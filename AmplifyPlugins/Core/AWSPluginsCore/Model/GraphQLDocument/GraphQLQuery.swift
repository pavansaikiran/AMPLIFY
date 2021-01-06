//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify

/// A concrete implementation of `SingleDirectiveGraphQLDocument` that represents a query operation.
public struct GraphQLQuery: SingleDirectiveGraphQLDocument {

    public init(operationType: GraphQLOperationType,
                name: String,
                inputs: [GraphQLParameterName: GraphQLDocumentInput],
                selectionSet: SelectionSet?) {
        self.operationType = operationType
        self.name = name
        self.inputs = inputs
        self.selectionSet = selectionSet
    }

    @available(*, deprecated, message: """
    Init with modelType is deprecated, use init with modelSchema instead.
    """)
    public init(modelType: Model.Type) {
        self.init(modelSchema: modelType.schema)
    }

    public init(modelSchema: ModelSchema) {
        self.selectionSet = SelectionSet(fields: modelSchema.graphQLFields)
    }

    public var name: String = ""

    public var operationType: GraphQLOperationType = .query

    public var inputs: [GraphQLParameterName: GraphQLDocumentInput] = [:]

    public var selectionSet: SelectionSet?
}
