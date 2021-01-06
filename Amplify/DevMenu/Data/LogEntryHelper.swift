//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

/// Helper class to fetch log entry related information
@available(iOS 13.0, *)
struct LogEntryHelper {

    /// Date formatter instance for date formatting
    private static let dateFormatter: DateFormatter = {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSS"
            return formatter
     }()

    /// Helper function to get current time in a specified format
    static func dateString(from date: Date) -> String {
            return dateFormatter.string(from: date)
    }

    /// Helper function to fetch logs from `PersistentLoggingPlugin`
    static func getLogHistory() -> [LogEntryItem] {
        if let loggingPlugin: PersistentLoggingPlugin =  Amplify.Logging.plugin as? PersistentLoggingPlugin {
            if let logger: PersistentLogWrapper = loggingPlugin.default as? PersistentLogWrapper {
                return logger.getLogHistory()
            }
        }

        return [LogEntryItem]()
    }
}
