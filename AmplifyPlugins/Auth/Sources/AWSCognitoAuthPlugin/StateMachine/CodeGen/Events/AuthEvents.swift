//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

struct AuthEvent: StateMachineEvent {

    enum EventType: Equatable {

        case configureAuth(AuthConfiguration)

        case fetchCachedCredentials(AuthConfiguration)

        case receivedCachedCredentials(AmplifyCredentials)

        case cachedCredentialsFailed

        case configureAuthentication(AuthConfiguration, AmplifyCredentials)

        case configureAuthorization(AuthConfiguration, AmplifyCredentials)

        case authenticationConfigured(AuthConfiguration, AmplifyCredentials)

        case authorizationConfigured
    }

    var id: String

    let eventType: EventType

    var time: Date?

    var type: String {
        switch eventType {
        case .configureAuth: return "AuthEvent.configureAuth"
        case .fetchCachedCredentials: return "AuthEvent.fetchCachedCredentials"
        case .configureAuthentication: return "AuthEvent.configureAuthentication"
        case .configureAuthorization: return "AuthEvent.configureAuthorization"
        case .authenticationConfigured: return "AuthEvent.authenticationConfigured"
        case .authorizationConfigured: return "AuthEvent.authorizationConfigured"
        case .receivedCachedCredentials: return "AuthEvent.receivedCachedCredentials"
        case .cachedCredentialsFailed: return "AuthEvent.cachedCredentialsFailed"
        }
    }

    init(id: String = UUID().uuidString,
         eventType: EventType,
         time: Date? = Date()) {
        self.id = id
        self.eventType = eventType
        self.time = time
    }

}
