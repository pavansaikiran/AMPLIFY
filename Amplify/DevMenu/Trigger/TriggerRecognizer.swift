//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

/// A protocol to be implemented for recognizing user interaction events
/// which notifies a `TriggerDelegate` if it has one
public protocol TriggerRecognizer {
    /// Update trigger delegate so that it can be notified in case a trigger happens
    func updateTriggerDelegate(delegate: TriggerDelegate)
}
