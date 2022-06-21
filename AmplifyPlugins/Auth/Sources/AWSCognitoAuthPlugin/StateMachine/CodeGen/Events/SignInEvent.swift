//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
import Foundation
import AWSCognitoIdentityProvider
import Amplify

struct SignInEvent: StateMachineEvent {

    enum EventType: Equatable {

        static func == (lhs: SignInEvent.EventType, rhs: SignInEvent.EventType) -> Bool {
            //TODO: Fix
            return false
        }

        case receivedSMSChallenge(RespondToAuthChallenge)

        case verifySMSChallenge(String)


    }

    let id: String
    let eventType: EventType
    let time: Date?

    var type: String {
        switch eventType {
        case .receivedSMSChallenge: return "SignInEvent.respondWithSMSChallenge"
        case .verifySMSChallenge: return "SignInEvent.verifySMSChallenge"
        }
    }

    init(id: String = UUID().uuidString,
         eventType: EventType,
         time: Date? = nil) {
        self.id = id
        self.eventType = eventType
        self.time = time
    }
}
