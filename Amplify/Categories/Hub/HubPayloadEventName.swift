//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public typealias HubPayloadEventName = String

public protocol HubPayloadEventNameable {
    var eventName: HubPayloadEventName { get }
}
