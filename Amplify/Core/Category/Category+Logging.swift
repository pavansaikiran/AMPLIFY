//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public extension Category {
    /// A default logger for the category
    var log: Logger {
        Amplify.Logging.logger(forCategory: categoryType.displayName)
    }
}
