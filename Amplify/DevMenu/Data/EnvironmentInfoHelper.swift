//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import UIKit

/// Helper class to fetch Developer Environment Information
@available(iOS 13.0.0, *)
struct EnvironmentInfoHelper {

    static let environmentInfoSourceFileName = "local-env-info"

    static func fetchDeveloperInformationFromJson(filename: String) -> [EnvironmentInfoItem] {
        guard let url = Bundle.main.url(forResource: filename, withExtension: "json") else {
            Amplify.Logging.error(DevMenuStringConstants.logTag + "Error : json file doesn't exist")
            return [EnvironmentInfoItem]()
        }

        do {
            let jsonData = try Data(contentsOf: url)
            let decoder = JSONDecoder()
            let environmentInfo = try decoder.decode(DevEnvironmentInfo.self, from: jsonData)
            return getDeveloperEnvironmentInformation(devEnvInfo: environmentInfo)
        } catch {
            Amplify.Logging.error(DevMenuStringConstants.logTag + "Error : json file parsing failed")
            return [EnvironmentInfoItem]()
        }
    }

    static func getDeveloperEnvironmentInformation(devEnvInfo: DevEnvironmentInfo) -> [EnvironmentInfoItem] {
        return [
            EnvironmentInfoItem(type: .nodejsVersion(devEnvInfo.nodejsVersion)),
            EnvironmentInfoItem(type: .npmVersion(devEnvInfo.npmVersion)),
            EnvironmentInfoItem(type: .amplifyCLIVersion(devEnvInfo.amplifyCLIVersion)),
            EnvironmentInfoItem(type: .podVersion(devEnvInfo.podVersion)),
            EnvironmentInfoItem(type: .xcodeVersion(devEnvInfo.xcodeVersion)),
            EnvironmentInfoItem(type: .osVersion(devEnvInfo.osVersion))
        ]
    }
}
