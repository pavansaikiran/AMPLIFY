//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Dispatch

extension MutationEvent {
    static func pendingMutationEvents(for modelId: Model.Identifier,
                                      storageAdapter: StorageEngineAdapter) async -> DataStoreResult<[MutationEvent]> {
        await pendingMutationEvents(for: [modelId], storageAdapter: storageAdapter)
    }

    static func pendingMutationEvents(for modelIds: [Model.Identifier],
                                      storageAdapter: StorageEngineAdapter) async -> DataStoreResult<[MutationEvent]> {
        let fields = MutationEvent.keys
        let predicate = (fields.inProcess == false || fields.inProcess == nil)
        var queriedMutationEvents: [MutationEvent] = []
        var queryError: DataStoreError?
        let chunkedArrays = modelIds.chunked(into: SQLiteStorageEngineAdapter.maxNumberOfPredicates)
        for chunkedArray in chunkedArrays {
            var queryPredicates: [QueryPredicateOperation] = []
            for id in chunkedArray {
                queryPredicates.append(QueryPredicateOperation(field: fields.modelId.stringValue,
                                                               operator: .equals(id)))
            }
            let groupedQueryPredicates =  QueryPredicateGroup(type: .or, predicates: queryPredicates)
            let final = QueryPredicateGroup(type: .and, predicates: [groupedQueryPredicates, predicate])
            let sort = QuerySortDescriptor(fieldName: fields.createdAt.stringValue, order: .ascending)
            let result = await storageAdapter.query(MutationEvent.self,
                                                            predicate: final,
                                                            sort: [sort],
                                                            paginationInput: nil)
            switch result {
            case .success(let mutationEvents):
                queriedMutationEvents.append(contentsOf: mutationEvents)
            case .failure(let error):
                queryError = error
                break
            }
        }
        if let queryError = queryError {
            return .failure(queryError)
        } else {
            return .success(queriedMutationEvents)
        }
    }
}
