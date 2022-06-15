//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

extension StateMachineEvent {

    var isAuthEvent: AuthEvent.EventType? {
        guard let authEvent = (self as? AuthEvent)?.eventType else {
            return nil
        }
        return authEvent
    }

    var isAuthorizationEvent: AuthorizationEvent.EventType? {
        guard let authZEvent = (self as? AuthorizationEvent)?.eventType else {
            return nil
        }
        return authZEvent
    }

    var isRefreshSessionEvent: RefreshSessionEvent.EventType? {
        guard let refreshSessionEvent = (self as? RefreshSessionEvent)?.eventType else {
            return nil
        }
        return refreshSessionEvent
    }

    var isFetchSessionEvent: FetchAuthSessionEvent.EventType? {
        guard let fetchSessionEvent = (self as? FetchAuthSessionEvent)?.eventType else {
            return nil
        }
        return fetchSessionEvent
    }
    
}

