//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Combine
import AWSPluginsCore
import Foundation

final public class AWSDataStorePlugin: DataStoreCategoryPlugin {

    public var key: PluginKey = "awsDataStorePlugin"

    /// `true` if any models are syncable. Resolved during configuration phase
    var isSyncEnabled: Bool

    /// The listener on hub events unsubscribe token
    var hubListener: UnsubscribeToken?

    /// The Publisher that sends mutation events to subscribers
    var dataStorePublisher: ModelSubcriptionBehavior

    var dispatchedModelSyncedEvents: [ModelName: AtomicValue<Bool>]

    let modelRegistration: AmplifyModelRegistration

    /// The DataStore configuration
    let dataStoreConfiguration: DataStoreConfiguration

    /// A queue that regulates the execution of operations. This will be instantiated during initalization phase,
    /// and is clearable by `reset()`. This is implicitly unwrapped to be destroyed when resetting.
    var operationQueue: OperationQueue!

    let validAPIPluginKey: String

    let validAuthPluginKey: String

    var storageEngine: StorageEngineBehavior!
    var storageEngineInitQueue = DispatchQueue(label: "AWSDataStorePlugin.storageEngineInitQueue")
    var storageEngineBehaviorFactory: StorageEngineBehaviorFactory

    var iStorageEngineSink: Any?
    var storageEngineSink: AnyCancellable? {
        get {
            if let iStorageEngineSink = iStorageEngineSink as? AnyCancellable {
                return iStorageEngineSink
            }
            return nil
        }
        set {
            iStorageEngineSink = newValue
        }
    }

    /// No-argument init that uses defaults for all providers
    public init(modelRegistration: AmplifyModelRegistration,
                configuration dataStoreConfiguration: DataStoreConfiguration = .default) {
        self.modelRegistration = modelRegistration
        self.dataStoreConfiguration = dataStoreConfiguration
        self.isSyncEnabled = false
        self.operationQueue = OperationQueue()
        self.validAPIPluginKey =  "awsAPIPlugin"
        self.validAuthPluginKey = "awsCognitoAuthPlugin"
        self.storageEngineBehaviorFactory =
            StorageEngine.init(isSyncEnabled:dataStoreConfiguration:validAPIPluginKey:validAuthPluginKey:modelRegistryVersion:userDefault:)
        self.dataStorePublisher = DataStorePublisher()
        self.dispatchedModelSyncedEvents = [:]
    }

    /// Internal initializer for testing
    init(modelRegistration: AmplifyModelRegistration,
         configuration dataStoreConfiguration: DataStoreConfiguration = .default,
         storageEngineBehaviorFactory: StorageEngineBehaviorFactory? = nil,
         dataStorePublisher: ModelSubcriptionBehavior,
         operationQueue: OperationQueue = OperationQueue(),
         validAPIPluginKey: String,
         validAuthPluginKey: String) {
        self.modelRegistration = modelRegistration
        self.dataStoreConfiguration = dataStoreConfiguration
        self.operationQueue = operationQueue
        self.isSyncEnabled = false
        self.storageEngineBehaviorFactory = storageEngineBehaviorFactory ??
            StorageEngine.init(isSyncEnabled:dataStoreConfiguration:validAPIPluginKey:validAuthPluginKey:modelRegistryVersion:userDefault:)
        self.dataStorePublisher = dataStorePublisher
        self.dispatchedModelSyncedEvents = [:]
        self.validAPIPluginKey = validAPIPluginKey
        self.validAuthPluginKey = validAuthPluginKey
    }

    /// By the time this method gets called, DataStore will already have invoked
    /// `AmplifyModelRegistration.registerModels`, so we can inspect those models to derive isSyncEnabled, and pass
    /// them to `StorageEngine.setUp(modelSchemas:)`
    public func configure(using amplifyConfiguration: Any?) throws {
        modelRegistration.registerModels(registry: ModelRegistry.self)
        for modelSchema in ModelRegistry.modelSchemas {
            dispatchedModelSyncedEvents[modelSchema.name] = AtomicValue(initialValue: false)
        }
        resolveSyncEnabled()
        ModelListDecoderRegistry.registerDecoder(DataStoreListDecoder.self)
    }

    /// Initializes the underlying storage engine
    /// - Returns: success if the engine is successfully initialized or
    ///            a failure with a DataStoreError
    func initStorageEngine() -> DataStoreResult<Void> {
        storageEngineInitQueue.sync {
            if storageEngine != nil {
                return .successfulVoid
            }
            var result: DataStoreResult<Void>
            do {
                if self.dataStorePublisher == nil {
                    self.dataStorePublisher = DataStorePublisher()
                }
                try resolveStorageEngine(dataStoreConfiguration: dataStoreConfiguration)
                try storageEngine.setUp(modelSchemas: ModelRegistry.modelSchemas)
                try storageEngine.applyModelMigrations(modelSchemas: ModelRegistry.modelSchemas)
                result = .successfulVoid
            } catch {
                result = .failure(causedBy: error)
                log.error(error: error)
            }
            return result
        }
    }

    /// Initializes the underlying storage engine and starts the syncing process
    /// - Parameter completion: completion handler called with a success if the sync process started
    ///                         or with a DataStoreError in case of failure
    func initStorageEngineAndStartSync(completion: @escaping DataStoreCallback<Void> = { _ in }) {
        if storageEngine != nil {
            completion(.successfulVoid)
            return
        }

        switch initStorageEngine() {
        case .success:
            storageEngine.startSync { result in

                self.operationQueue.operations.forEach { operation in
                    if let operation = operation as? DataStoreObserveQueryOperationResettable {
                        operation.startObserveQuery(with: self.storageEngine)
                    }
                }
                completion(result)
            }
        case .failure(let error):
            completion(.failure(causedBy: error))
        }
    }

    func resolveStorageEngine(dataStoreConfiguration: DataStoreConfiguration) throws {
        guard storageEngine == nil else {
            return
        }

        storageEngine = try storageEngineBehaviorFactory(isSyncEnabled,
                                                         dataStoreConfiguration,
                                                         validAPIPluginKey,
                                                         validAuthPluginKey,
                                                         modelRegistration.version,
                                                         UserDefaults.standard)

        setupStorageSink()
    }

    // MARK: Private

    private func resolveSyncEnabled() {
        isSyncEnabled = ModelRegistry.hasSyncableModels
    }

    private func setupStorageSink() {
        storageEngineSink = storageEngine
            .publisher
            .sink(
                receiveCompletion: { [weak self] in self?.onReceiveCompletion(completed: $0) },
                receiveValue: { [weak self] in self?.onReceiveValue(receiveValue: $0) }
            )
    }

    private func onReceiveCompletion(completed: Subscribers.Completion<DataStoreError>) {
        switch completed {
        case .failure(let dataStoreError):
            log.error("StorageEngine completed with error: \(dataStoreError)")
        case .finished:
            break
        }
        stop { result in
            switch result {
            case .success:
                self.log.info("Stopping DataStore successful.")
                return
            case .failure(let error):
                self.log.error("Failed to stop StorageEngine with error: \(error)")
            }
        }
    }

    func onReceiveValue(receiveValue: StorageEngineEvent) {

        switch receiveValue {
        case .started:
            break
        case .mutationEvent(let mutationEvent):
            dataStorePublisher.send(input: mutationEvent)
        case .modelSyncedEvent(let modelSyncedEvent):
            log.verbose("Emitting DataStore event: modelSyncedEvent \(modelSyncedEvent)")
            let modelSyncedEventPayload = HubPayload(eventName: HubPayload.EventName.DataStore.modelSynced,
                                                     data: modelSyncedEvent)
            Amplify.Hub.dispatch(to: .dataStore, payload: modelSyncedEventPayload)
            dispatchedModelSyncedEvents[modelSyncedEvent.modelName]?.set(true)
        case .syncQueriesReadyEvent:
            log.verbose("[Lifecycle event 4]: syncQueriesReady")
            let syncQueriesReadyEventPayload = HubPayload(eventName: HubPayload.EventName.DataStore.syncQueriesReady)
            Amplify.Hub.dispatch(to: .dataStore, payload: syncQueriesReadyEventPayload)
        case .readyEvent:
            log.verbose("[Lifecycle event 6]: ready")
            let readyEventPayload = HubPayload(eventName: HubPayload.EventName.DataStore.ready)
            Amplify.Hub.dispatch(to: .dataStore, payload: readyEventPayload)
        }
    }

    public func reset() async {
        if operationQueue != nil {
            operationQueue = nil
        }
        dispatchedModelSyncedEvents = [:]
        if let listener = hubListener {
            Amplify.Hub.removeListener(listener)
            hubListener = nil
        }
        if let resettable = storageEngine as? Resettable {
            log.verbose("Resetting storageEngine")
            await resettable.reset()
            self.log.verbose("Resetting storageEngine: finished")
        }
    }

}

extension AWSDataStorePlugin: AmplifyVersionable { }
