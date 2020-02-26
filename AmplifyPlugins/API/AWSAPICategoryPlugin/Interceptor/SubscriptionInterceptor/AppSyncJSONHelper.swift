//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import AppSyncRealTimeClient

struct AppSyncJSONHelper {

    static func base64AuthenticationBlob(_ header: AuthenticationHeader ) -> String {
        let jsonEncoder = JSONEncoder()
        do {
            let jsonHeader = try jsonEncoder.encode(header)
            Amplify.Logging.verbose("Header - \(String(describing: String(data: jsonHeader, encoding: .utf8)))")
            return jsonHeader.base64EncodedString()
        } catch {
            Amplify.Logging.error(error.localizedDescription)
        }
        return ""
    }
}
