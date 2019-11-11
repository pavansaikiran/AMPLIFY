//
// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Licensed under the Amazon Software License
// http://aws.amazon.com/asl/
//

import Foundation
import Amplify

protocol ConnectionProvider: class {

    func connect()

    func disconnect()

    func sendConnectionInitMessage()

    func sendStartSubscriptionMessage(subscriptionItem: SubscriptionItem)

    func sendUnsubscribeMessage(identifier: String)

    func setListener(_ callback: @escaping ConnectionProviderCallback)
}

typealias ConnectionProviderCallback = (ConnectionProviderEvent) -> Void

enum ConnectionProviderEvent {

    case connection(ConnectionState)

    // Keep alive ping from the service
    case keepAlive

    // Subscription has been connected to the connection
    case subscriptionConnected(identifier: String)

    // Subscription has been disconnected from the connection
    case subscriptionDisconnected(identifier: String)

    // Data received on the connection
    case data(identifier: String, payload: [String: JSONValue])

    // Subscription related error
    case subscriptionError(String, ConnectionProviderError)

    // Unknown error
    case unknownError(ConnectionProviderError)
}

// Synchronized to the state of the underlying websocket connection
enum ConnectionState {
    // The websocket connection was created
    case connecting

    // The websocket connection has been established
    case connected

    // The websocket connection has been disconnected
    case disconnected(error: ConnectionProviderError?)
}
