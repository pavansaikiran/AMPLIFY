//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import AWSPluginsCore
import Combine

enum IncomingSubscriptionEventPublisherEvent {
    case mutationEvent(MutationSync<AnyModel>)
}

@available(iOS 13.0, *)
protocol IncomingSubscriptionEventPublisher {
    var publisher: AnyPublisher<IncomingSubscriptionEventPublisherEvent, DataStoreError> { get }
    func kill()
}
