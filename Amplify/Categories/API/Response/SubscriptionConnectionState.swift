//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public enum SubscriptionConnectionState {

     /// The subscription is in process of connecting
    case connecting

    /// The subscription has connected and is receiving events from the service
    case connected

    /// The subscription has been disconnected because of a lifecycle event or manual disconnect request
    case disconnected
}
