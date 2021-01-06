//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

/// Implement this protocol to get notified of the trigger events recognized by
/// a `TriggerRecognizer`
public protocol TriggerDelegate: AnyObject {
    func onTrigger(triggerRecognizer: TriggerRecognizer)
}
