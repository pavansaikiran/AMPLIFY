//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
import AmplifyPlugins
import AWSLocation

@testable import Amplify
@testable import AWSLocationGeoPlugin
@testable import AmplifyTestCommon

class AWSLocationGeoPluginIntergrationTests: XCTestCase {
    let timeout = 30.0
    let searchText = "coffee shop"
    let coordinates = Geo.Coordinates(latitude: 39.7392, longitude: -104.9903)

    override func setUp() {
        continueAfterFailure = false
        do {
            try Amplify.add(plugin: AWSCognitoAuthPlugin())
            try Amplify.add(plugin: AWSLocationGeoPlugin())
            try Amplify.configure()
        } catch {
            XCTFail("Failed to initialize and configure Amplify \(error)")
        }
        XCTAssertNotNil(Amplify.Geo.plugin)
    }

    override func tearDown() {
        Amplify.reset()
    }

    func testSearchForText() {
        let expResult = expectation(description: "Receive result")

        let options = Geo.SearchForTextOptions(area: .near(coordinates))
        Amplify.Geo.search(for: searchText, options: options) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed with error: \(error)")
            case .success(let places):
                XCTAssertFalse(places.isEmpty)
                expResult.fulfill()
            }
        }

        waitForExpectations(timeout: timeout)
    }

    func testSearchForCoordinates() {
        let expResult = expectation(description: "Receive result")

        Amplify.Geo.search(for: coordinates) { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed with error: \(error)")
            case .success(let places):
                XCTAssertFalse(places.isEmpty)
                XCTAssertNotNil(places.first?.coordinates)
                expResult.fulfill()
            }
        }

        waitForExpectations(timeout: timeout)
    }

    func testDefaultMap() {
        let expResult = expectation(description: "Receive result")

        Amplify.Geo.defaultMap { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed with error: \(error)")
            case .success(let map):
                XCTAssertNotNil(map)
                XCTAssertNotNil(map.mapName)
                XCTAssertNotNil(map.style)
                XCTAssertNotNil(map.styleURL)
                expResult.fulfill()
            }
        }

        waitForExpectations(timeout: timeout)
    }

    func testAvailtableMaps() {
        let expResult = expectation(description: "Receive result")

        Amplify.Geo.availableMaps { result in
            switch result {
            case .failure(let error):
                XCTFail("Failed with error: \(error)")
            case .success(let maps):
                XCTAssertFalse(maps.isEmpty)
                XCTAssertNotNil(maps.first?.mapName)
                XCTAssertNotNil(maps.first?.style)
                XCTAssertNotNil(maps.first?.styleURL)
                expResult.fulfill()
            }
        }

        waitForExpectations(timeout: timeout)
    }

    func testGetEscapeHatch() throws {
        let plugin = try Amplify.Geo.getPlugin(for: "awsLocationGeoPlugin")
        guard let locationPlugin = plugin as? AWSLocationGeoPlugin else {
            XCTFail("Could not get plugin of type AWSLocationGeoPlugin")
            return
        }
        let awsLocation = locationPlugin.getEscapeHatch()
        XCTAssertNotNil(awsLocation)
    }
}
