//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import AWSPluginsCore
import Foundation

struct PersistCredentials: Action {

    let identifier = "PersistCredentials"

    let credentials: AmplifyCredentials

    func execute(withDispatcher dispatcher: EventDispatcher, environment: Environment) {

        logVerbose("\(#fileID) Starting execution", environment: environment)

        let credentialStoreClient = (environment as? AuthEnvironment)?.credentialStoreClientFactory()

        Task {
            let event: StateMachineEvent
            do {
                try await credentialStoreClient?.storeData(data: .amplifyCredentials(credentials))
                event = AuthorizationEvent(eventType: .sessionEstablished(credentials))
            } catch {
                let authorizationError = AuthorizationError.service(error: error)
                event = AuthorizationEvent(eventType: .throwError(authorizationError))
            }
            logVerbose("\(#fileID) Sending event \(event.type)", environment: environment)
            dispatcher.send(event)
        }

    }
}

extension PersistCredentials: DefaultLogger { }

extension PersistCredentials: CustomDebugDictionaryConvertible {
    var debugDictionary: [String: Any] {
        [
            "identifier": identifier
        ]
    }
}

extension PersistCredentials: CustomDebugStringConvertible {
    var debugDescription: String {
        debugDictionary.debugDescription
    }
}
