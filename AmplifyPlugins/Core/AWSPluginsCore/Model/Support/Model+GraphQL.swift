//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify

typealias GraphQLInput = [String: Any?]

/// Extension that adds GraphQL specific utilities to concret types of `Model`.
extension Model {

    /// Returns an array of model fields sorted by predefined rules (see ModelSchema+sortedFields)
    /// and filtered according the following criteria:
    /// - fields are not read-only
    /// - fields exist on the model
    private func fieldsForMutation(_ modelSchema: ModelSchema) -> [(ModelField, Any?)] {
        modelSchema.sortedFields.compactMap { field in
            guard !field.isReadOnly,
                  let fieldValue = getFieldValue(for: field.name,
                                                 modelSchema: modelSchema) else {
                return nil
            }
            return (field, fieldValue)
        }
    }

    /// Returns the input used for mutations
    /// - Parameter modelSchema: model's schema
    /// - Returns: A key-value map of the GraphQL mutation input
    func graphQLInputForMutation(_ modelSchema: ModelSchema) -> GraphQLInput {
        var input: GraphQLInput = [:]

        // filter existing non-readonly fields
        let fields = fieldsForMutation(modelSchema)

        for (modelField, modelFieldValue) in fields {
            let name = modelField.name

            guard let value = modelFieldValue else {
                // don't invalidate fields of type .model
                // as we'll take care of this later on (see line 61)
                if case .model = modelField.type {
                    continue
                }
                input.updateValue(nil, forKey: name)
                continue
            }

            switch modelField.type {
            case .collection:
                // we don't currently support this use case
                continue
            case .date, .dateTime, .time:
                if let date = value as? TemporalSpec {
                    input[name] = date.iso8601String
                } else {
                    input[name] = value
                }
            case .enum:
                input[name] = (value as? EnumPersistable)?.rawValue
            case .model:
                // get the associated model target names and their values
                let associatedModelIds = zip(getFieldNameForAssociatedModels(modelField: modelField),
                                             getModelIdentifierValues(from: value, modelSchema: modelSchema))
                for (fieldName, fieldValue) in associatedModelIds {
                    input[fieldName] = fieldValue
                }
            case .embedded, .embeddedCollection:
                if let encodable = value as? Encodable {
                    let jsonEncoder = JSONEncoder(dateEncodingStrategy: ModelDateFormatting.encodingStrategy)
                    do {
                        let data = try jsonEncoder.encode(encodable.eraseToAnyEncodable())
                        input[name] = try JSONSerialization.jsonObject(with: data)
                    } catch {
                        preconditionFailure("Could not turn into json object from \(value)")
                    }
                }
            case .string, .int, .double, .timestamp, .bool:
                input[name] = value
            }
        }
        return input
    }

    /// Retrieve the custom primary key's value used for the GraphQL input.
    /// Only a subset of data types are applicable as custom indexes such as
    /// `date`, `dateTime`, `time`, `enum`, `string`, `double`, and `int`.
    func graphQLInputForPrimaryKey(modelFieldName: ModelFieldName,
                                   modelSchema: ModelSchema) -> String? {

        guard let modelField = modelSchema.field(withName: modelFieldName) else {
            return nil
        }

        let fieldValueOptional = getFieldValue(for: modelField.name, modelSchema: modelSchema)

        guard let fieldValue = fieldValueOptional else {
            return nil
        }

        // swiftlint:disable:next syntactic_sugar
        guard case .some(Optional<Any>.some(let value)) = fieldValue else {
            return nil
        }

        switch modelField.type {
        case .date, .dateTime, .time:
            if let date = value as? TemporalSpec {
                return date.iso8601String
            } else {
                return nil
            }
        case .enum:
            return (value as? EnumPersistable)?.rawValue
        case .model, .embedded, .embeddedCollection:
            return nil
        case .string, .double, .int:
            return String(describing: value)
        default:
            return nil
        }
    }

    /// Given a model and its schema, returns the values of its identifier (primary key).
    /// The return value is an array as models can have a composite identifier.
    /// - Parameters:
    ///   - value: model value
    ///   - modelSchema: model's schema
    /// - Returns: array of values of its primary key
    private func getModelIdentifierValues(from value: Any, modelSchema: ModelSchema) -> [Persistable] {
        if let modelValue = value as? Model {
            return modelValue.identifier(schema: modelSchema).values
        } else if let value = value as? [String: JSONValue] {
            var primaryKeyValues = [Persistable]()
            for field in modelSchema.primaryKey.fields {
                if case .string(let primaryKeyValue) = value[field.name] {
                    primaryKeyValues.append(primaryKeyValue)
                }
            }
            return primaryKeyValues
        }
        return []
    }

    private func getFieldValue(for modelFieldName: String, modelSchema: ModelSchema) -> Any?? {
        if let jsonModel = self as? JSONValueHolder {
            return jsonModel.jsonValue(for: modelFieldName, modelSchema: modelSchema) ?? nil
        } else {
            return self[modelFieldName] ?? nil
        }
    }

    /// Retrieves the GraphQL field name that associates the current model with the target model.
    /// By default, this is the current model + the associated Model + "Id", For example "comment" + "Post" + "Id"
    /// This information is also stored in the schema as `targetName` which is codegenerated to be the same as the
    /// default or an explicit field specified by the developer.
    private func getFieldNameForAssociatedModels(modelField: ModelField) -> [String] {
        let defaultFieldName = modelName.camelCased() + modelField.name.pascalCased() + "Id"
        if case let .belongsTo(_, targetNames) = modelField.association, !targetNames.isEmpty {
            return targetNames
        } else if case let .hasOne(_, targetNames) = modelField.association,
                  !targetNames.isEmpty {
            return targetNames
        }

        return [defaultFieldName]
    }

}
