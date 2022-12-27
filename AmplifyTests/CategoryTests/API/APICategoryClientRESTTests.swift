//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest

// Only @testable so we can get access to `Amplify.reset()`
@testable import Amplify

@testable import AmplifyTestCommon

class APICategoryClientRESTTests: XCTestCase {
    var mockAmplifyConfig: AmplifyConfiguration!

    override func setUp() {
        Amplify.reset()

        let apiConfig = APICategoryConfiguration(
            plugins: ["MockAPICategoryPlugin": true]
        )

        mockAmplifyConfig = AmplifyConfiguration(api: apiConfig)
    }

    func testGet() throws {
        let plugin = try makeAndAddMockPlugin()
        let methodWasInvokedOnPlugin = expectation(description: "method was invoked on plugin")
        plugin.listeners.append { message in
            if message == "get" {
                methodWasInvokedOnPlugin.fulfill()
            }
        }

        Amplify.API.get(request: RESTRequest()) { _ in }

        waitForExpectations(timeout: 0.5)
    }

    func testCacheInRequest() {
        let request = RESTRequest(apiName: "someapi")
        XCTAssertEqual(request.headers?["Cache-Control"], "no-store")
    }

    func testCustomCacheInRequest() {
        let request = RESTRequest(apiName: "someapi", headers: ["Cache-Control": "private"])
        XCTAssertEqual(request.headers?["Cache-Control"], "private")
    }

    // MARK: - Utilities

    func makeAndAddMockPlugin() throws -> MockAPICategoryPlugin {
        let plugin = MockAPICategoryPlugin()
        try Amplify.add(plugin: plugin)
        try Amplify.configure(mockAmplifyConfig)
        return plugin
    }

}
