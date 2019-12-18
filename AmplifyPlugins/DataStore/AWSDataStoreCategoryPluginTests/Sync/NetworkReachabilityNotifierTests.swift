//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import XCTest
import Reachability
import Combine
@testable import AWSDataStoreCategoryPlugin

class NetworkReachabilityNotifierTests: XCTestCase {
    var notification: Notification!
    var notifier: NetworkReachabilityNotifier!

    override func setUp() {
        notifier = NetworkReachabilityNotifier(host: "localhost",
                                               allowsCellularAccess: true,
                                               reachabilityFactory: MockNetworkReachabilityProvidingFactory.self)
        MockReachability.iConnection = .wifi
    }

    func testWifiConnectivity() {
        MockReachability.iConnection = .wifi
        let expect = expectation(description: ".sink receives value")
        let cancellable = notifier.publisher.sink(receiveCompletion: { _ in
            XCTFail("Not expecting any error")
        }, receiveValue: { value in
            XCTAssert(value.isOnline)
            expect.fulfill()
        })
        notification = Notification.init(name: .reachabilityChanged)
        NotificationCenter.default.post(notification)

        waitForExpectations(timeout: 1.0)
        cancellable.cancel()
    }
    func testCellularConnectivity() {
        MockReachability.iConnection = .wifi
        let expect = expectation(description: ".sink receives value")
        let cancellable = notifier.publisher.sink(receiveCompletion: { _ in
            XCTFail("Not expecting any error")
        }, receiveValue: { value in
            XCTAssert(value.isOnline)
            expect.fulfill()
        })

        notification = Notification.init(name: .reachabilityChanged)
        NotificationCenter.default.post(notification)

        waitForExpectations(timeout: 1.0)
        cancellable.cancel()

    }

    func testNoConnectivity() {
        MockReachability.iConnection = .unavailable
        let expect = expectation(description: ".sink receives value")
        let cancellable = notifier.publisher.sink(receiveCompletion: { _ in
            XCTFail("Not expecting any error")
        }, receiveValue: { value in
            XCTAssertFalse(value.isOnline)
            expect.fulfill()
        })

        notification = Notification.init(name: .reachabilityChanged)
        NotificationCenter.default.post(notification)

        waitForExpectations(timeout: 1.0)
        cancellable.cancel()
    }

    func testWifiConnectivity_publisherGoesOutOfScope() {
        MockReachability.iConnection = .wifi
        let expect = expectation(description: ".sink receives value")
        let cancellable = notifier.publisher.sink(receiveCompletion: { _ in
            expect.fulfill()
        }, receiveValue: { _ in
            XCTAssertFalse(true)
        })

        notifier = nil
        notification = Notification.init(name: .reachabilityChanged)
        NotificationCenter.default.post(notification)

        waitForExpectations(timeout: 1.0)
        cancellable.cancel()
    }
}

class MockNetworkReachabilityProvidingFactory: NetworkReachabilityProvidingFactory {
    public static func make(for hostname: String) -> NetworkReachabilityProviding? {
        return MockReachability()
    }
}

class MockReachability: NetworkReachabilityProviding {
    var allowsCellularConnection = true
    static var iConnection = Reachability.Connection.wifi
    var connection: Reachability.Connection {
        get {
            return MockReachability.iConnection
        }
        set(conn) {
            MockReachability.iConnection = conn
        }
    }

    var notificationCenter: NotificationCenter = .default

    func setConnection(connection: Reachability.Connection) {
        self.connection = connection
    }

    func startNotifier() throws {
    }

    func stopNotifier() {
    }
}
