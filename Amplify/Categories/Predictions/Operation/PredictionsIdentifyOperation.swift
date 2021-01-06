//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

public protocol PredictionsIdentifyOperation: AmplifyOperation<
    PredictionsIdentifyRequest,
    IdentifyResult,
    PredictionsError
> { }

public extension HubPayload.EventName.Predictions {
    static let identifyLabels = "Predictions.identifyLabels"
    static let identifyCelebrities = "Predictions.identifyCelebrities"
}
