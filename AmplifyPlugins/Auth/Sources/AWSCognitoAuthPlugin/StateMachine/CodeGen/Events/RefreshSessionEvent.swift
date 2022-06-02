//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

struct RefreshSessionEvent: StateMachineEvent {
    enum EventType: Equatable {
        static func == (lhs: RefreshSessionEvent.EventType,
                        rhs: RefreshSessionEvent.EventType) -> Bool {
            // TODO: Fix
            return true
        }

        case refreshUnAuthAWSCredentials(IdentityID)

        case refreshAWSCredentialsWithUserPool(IdentityID, AWSCognitoUserPoolTokens, LoginsMapProvider)

        case refreshCognitoUserPool(AWSCognitoUserPoolTokens, IdentityID?)

        case refreshedCognitoUserPool(AWSCognitoUserPoolTokens)

        case fetchIdentityInfo(AWSCognitoUserPoolTokens)

        case refreshed(AmplifyCredentials)

        case throwError(RefreshSessionError)

    }

    let id: String
    let eventType: EventType
    let time: Date?

    var type: String {
        switch eventType {

        case .refreshUnAuthAWSCredentials:
            return "RefreshSessionEvent.refreshUnAuthAWSCredentials"
        case .refreshAWSCredentialsWithUserPool:
            return "RefreshSessionEvent.refreshAWSCredentialsWithUserPool"
        case .refreshCognitoUserPool:
            return "RefreshSessionEvent.refreshCognitoUserPool"
        case .refreshedCognitoUserPool:
            return "RefreshSessionEvent.refreshedCognitoUserPool"
        case .fetchIdentityInfo:
            return "RefreshSessionEvent.fetchIdentityInfo"
        case .refreshed:
            return "RefreshSessionEvent.refreshed"
        case .throwError:
            return "RefreshSessionEvent.throwError"
        }
    }

    init(
        id: String = UUID().uuidString,
        eventType: EventType,
        time: Date? = nil
    ) {
        self.id = id
        self.eventType = eventType
        self.time = time
    }
}

enum RefreshSessionError: Error {

    case noIdentityPool

    case noUserPool

    case notAuthorized

    case invalidIdentityID

    case noCredentialsToRefresh

    case service(Error)
}
