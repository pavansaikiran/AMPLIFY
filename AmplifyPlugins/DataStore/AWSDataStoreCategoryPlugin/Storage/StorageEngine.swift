//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Combine
import Foundation
import AWSPluginsCore

typealias StorageEngineBehaviorFactory =
    (DataStoreConfiguration,
    String,
    String,
    String,
    UserDefaults) throws -> StorageEngineBehavior

// swiftlint:disable type_body_length
final class StorageEngine: StorageEngineBehavior {
    // swiftlint:disable:next todo
    // TODO: Make this private once we get a mutation flow that passes the type of mutation as needed
    let storageAdapter: StorageEngineAdapter

    let validAPIPluginKey: String
    let validAuthPluginKey: String
    var signInListener: UnsubscribeToken?

    let dataStoreConfiguration: DataStoreConfiguration
    private let operationQueue: OperationQueue

    weak var syncEngine: RemoteSyncEngineBehavior?

    static var systemModelSchemas: [ModelSchema] {
        return [
            ModelSyncMetadata.schema,
            MutationEvent.schema,
            MutationSyncMetadata.schema
        ]
    }

    // Internal initializer used for testing, to allow lazy initialization of the SyncEngine. Note that the provided
    // storageAdapter must have already been set up with system models
    init(storageAdapter: StorageEngineAdapter,
         dataStoreConfiguration: DataStoreConfiguration,
         validAPIPluginKey: String,
         validAuthPluginKey: String
    ) {
        self.storageAdapter = storageAdapter
        self.dataStoreConfiguration = dataStoreConfiguration
        self.syncEngine = nil
        self.validAPIPluginKey = validAPIPluginKey
        self.validAuthPluginKey = validAuthPluginKey

        let operationQueue = OperationQueue()
        operationQueue.name = "com.amazonaws.StorageEngine"
        self.operationQueue = operationQueue
    }

    convenience init(dataStoreConfiguration: DataStoreConfiguration,
                     validAPIPluginKey: String = "awsAPIPlugin",
                     validAuthPluginKey: String = "awsCognitoAuthPlugin",
                     modelRegistryVersion: String,
                     userDefault: UserDefaults = UserDefaults.standard) throws {

        let key = kCFBundleNameKey as String
        let databaseName = Bundle.main.object(forInfoDictionaryKey: key) as? String ?? "app"

        let storageAdapter = try SQLiteStorageEngineAdapter(version: modelRegistryVersion, databaseName: databaseName)

        try storageAdapter.setUp(modelSchemas: StorageEngine.systemModelSchemas)
        if #available(iOS 13.0, *) {
            self.init(storageAdapter: storageAdapter,
                      dataStoreConfiguration: dataStoreConfiguration,
                      validAPIPluginKey: validAPIPluginKey,
                      validAuthPluginKey: validAuthPluginKey
            )
        } else {
            self.init(storageAdapter: storageAdapter,
                      dataStoreConfiguration: dataStoreConfiguration,
                      validAPIPluginKey: validAPIPluginKey,
                      validAuthPluginKey: validAuthPluginKey
            )
        }
    }

    func setUp(modelSchemas: [ModelSchema]) throws {
        try storageAdapter.setUp(modelSchemas: modelSchemas)
    }

    func applyModelMigrations(modelSchemas: [ModelSchema]) throws {
        try storageAdapter.applyModelMigrations(modelSchemas: modelSchemas)
    }

    public func save<M: Model>(_ model: M,
                               modelSchema: ModelSchema,
                               condition: QueryPredicate? = nil,
                               completion: @escaping DataStoreCallback<M>) {

        // swiftlint:disable:next todo
        // TODO: Refactor this into a proper request/result where the result includes metadata like the derived
        // mutation type
        let modelExists: Bool
        do {
            modelExists = try storageAdapter.exists(modelSchema,
                                                    withIdentifier: model.identifier(schema: modelSchema),
                                                    predicate: nil)
        } catch {
            let dataStoreError = DataStoreError.invalidOperation(causedBy: error)
            completion(.failure(dataStoreError))
            return
        }

        let mutationType = modelExists ? MutationEvent.MutationType.update : .create

        // If it is `create`, and there is a condition, and that condition is not `.all`, fail the request
        if mutationType == .create, let condition = condition, !condition.isAll {
            let dataStoreError = DataStoreError.invalidCondition(
                "Cannot apply a condition on model which does not exist.",
                "Save the model instance without a condition first.")
            completion(.failure(causedBy: dataStoreError))
        }

        let wrappedCompletion: DataStoreCallback<M> = { result in
            guard modelSchema.isSyncable else {
                completion(result)
                return
            }

            guard case .success(let savedModel) = result else {
                completion(result)
                return
            }

            if #available(iOS 13.0, *), let syncEngine = self.syncEngine {
                self.log.verbose("\(#function) syncing mutation for \(savedModel)")
                self.syncMutation(of: savedModel,
                                  modelSchema: modelSchema,
                                  mutationType: mutationType,
                                  predicate: condition,
                                  syncEngine: syncEngine,
                                  completion: completion)
            } else {
                completion(result)
            }
        }

        storageAdapter.save(model,
                            modelSchema: modelSchema,
                            condition: condition,
                            completion: wrappedCompletion)
    }

    func save<M: Model>(_ model: M, condition: QueryPredicate? = nil, completion: @escaping DataStoreCallback<M>) {
        save(model, modelSchema: model.schema, condition: condition, completion: completion)
    }

    @available(*, deprecated, message: "Use delete(:modelSchema:withIdentifier:predicate:completion")
    func delete<M: Model>(_ modelType: M.Type,
                          modelSchema: ModelSchema,
                          withId id: Model.Identifier,
                          condition: QueryPredicate? = nil,
                          completion: @escaping (DataStoreResult<M?>) -> Void) {
        let cascadeDeleteOperation = CascadeDeleteOperation(
            storageAdapter: storageAdapter,
            syncEngine: syncEngine,
            modelType: modelType, modelSchema: modelSchema,
            withIdentifier: DefaultModelIdentifier<M>.makeDefault(id: id),
            condition: condition,
            completion: { completion($0) }
        )
        operationQueue.addOperation(cascadeDeleteOperation)
    }

    func delete<M: Model>(_ modelType: M.Type,
                          modelSchema: ModelSchema,
                          withIdentifier identifier: ModelIdentifierProtocol,
                          condition: QueryPredicate?,
                          completion: @escaping DataStoreCallback<M?>) {
        let cascadeDeleteOperation = CascadeDeleteOperation(storageAdapter: storageAdapter,
                                                            syncEngine: syncEngine,
                                                            modelType: modelType, modelSchema: modelSchema,
                                                            withIdentifier: identifier,
                                                            condition: condition) { completion($0) }
        operationQueue.addOperation(cascadeDeleteOperation)

    }

    func delete<M: Model>(_ modelType: M.Type,
                          modelSchema: ModelSchema,
                          filter: QueryPredicate,
                          completion: @escaping DataStoreCallback<[M]>) {
        let cascadeDeleteOperation = CascadeDeleteOperation(storageAdapter: storageAdapter,
                                                            syncEngine: syncEngine,
                                                            modelType: modelType,
                                                            modelSchema: modelSchema,
                                                            filter: filter) { completion($0) }
        operationQueue.addOperation(cascadeDeleteOperation)
    }

    // swiftlint:disable:next function_parameter_count
    func query<M: Model>(_ modelType: M.Type,
                         modelSchema: ModelSchema,
                         predicate: QueryPredicate?,
                         sort: [QuerySortDescriptor]?,
                         paginationInput: QueryPaginationInput?,
                         completion: (DataStoreResult<[M]>) -> Void) {
        return storageAdapter.query(modelType,
                                    modelSchema: modelSchema,
                                    predicate: predicate,
                                    sort: sort,
                                    paginationInput: paginationInput,
                                    completion: completion)
    }

    func query<M: Model>(_ modelType: M.Type,
                         predicate: QueryPredicate? = nil,
                         sort: [QuerySortDescriptor]? = nil,
                         paginationInput: QueryPaginationInput? = nil,
                         completion: DataStoreCallback<[M]>) {
        query(modelType,
              modelSchema: modelType.schema,
              predicate: predicate,
              sort: sort,
              paginationInput: paginationInput,
              completion: completion)
    }

    func clear(completion: @escaping DataStoreCallback<Void>) {
        storageAdapter.clear(completion: completion)
    }

    @available(iOS 13.0, *)
    private func syncMutation<M: Model>(of savedModel: M,
                                        modelSchema: ModelSchema,
                                        mutationType: MutationEvent.MutationType,
                                        predicate: QueryPredicate? = nil,
                                        syncEngine: RemoteSyncEngineBehavior,
                                        completion: @escaping DataStoreCallback<M>) {
        let mutationEvent: MutationEvent
        do {
            var graphQLFilterJSON: String?
            if let predicate = predicate {
                graphQLFilterJSON = try GraphQLFilterConverter.toJSON(predicate,
                                                                      modelSchema: modelSchema)
            }

            mutationEvent = try MutationEvent(model: savedModel,
                                              modelSchema: modelSchema,
                                              mutationType: mutationType,
                                              graphQLFilterJSON: graphQLFilterJSON)

        } catch {
            let dataStoreError = DataStoreError(error: error)
            completion(.failure(dataStoreError))
            return
        }

        let mutationEventCallback: DataStoreCallback<MutationEvent> = { result in
            switch result {
            case .failure(let dataStoreError):
                completion(.failure(dataStoreError))
            case .success(let mutationEvent):
                self.log.verbose("\(#function) successfully submitted to sync engine \(mutationEvent)")
                completion(.success(savedModel))
            }
        }

        submitToSyncEngine(mutationEvent: mutationEvent,
                           syncEngine: syncEngine,
                           completion: mutationEventCallback)
    }

    @available(iOS 13.0, *)
    private func submitToSyncEngine(mutationEvent: MutationEvent,
                                    syncEngine: RemoteSyncEngineBehavior,
                                    completion: @escaping DataStoreCallback<MutationEvent>) {
        var mutationQueueSink: AnyCancellable?
        mutationQueueSink = syncEngine
            .submit(mutationEvent)
            .sink(
                receiveCompletion: { futureCompletion in
                    switch futureCompletion {
                    case .failure(let error):
                        completion(.failure(causedBy: error))
                    case .finished:
                        self.log.verbose("\(#function) Received successful completion")
                    }
                    mutationQueueSink?.cancel()
                    mutationQueueSink = nil

                }, receiveValue: { mutationEvent in
                    self.log.verbose("\(#function) saved mutation event: \(mutationEvent)")
                    completion(.success(mutationEvent))
                })
    }

}

extension StorageEngine: Resettable {
    func reset(onComplete: @escaping BasicClosure) {
        // TOOD: Perform cleanup on StorageAdapter, including releasing its `Connection` if needed
        onComplete()
    }
}

extension StorageEngine: DefaultLogger { } // swiftlint:disable:this file_length
