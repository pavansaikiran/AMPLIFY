//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
@testable import HSM

class StateMachineListenerTests: XCTestCase {

    var stateMachine: CounterStateMachine!
    var tokens = Set<CounterStateMachine.StateChangeListenerToken>()

    override func setUpWithError() throws {
        stateMachine = CounterStateMachine.logging()
    }

    func testNotifiesOnListen() async {
        await stateMachine.send(Counter.Event(id: "test", eventType: .increment))
        let subscribed = expectation(description: "subscribed")
        let notified = expectation(description: "notified")
        await stateMachine.listen { state in
            notified.fulfill()
            XCTAssertEqual(state.value, 1)
        }
        onSubscribe: {
            subscribed.fulfill()
        }
        .store(in: &tokens)

        await waitForExpectations(timeout: 0.1)
    }

    func testNotifiesOnStateChange() async {
        await stateMachine.send(Counter.Event(id: "test", eventType: .increment))
        let subscribed = expectation(description: "subscribed")
        let notified = expectation(description: "notified")
        notified.expectedFulfillmentCount = 2
        await stateMachine.listen { _ in
            notified.fulfill()
        }
        onSubscribe: {
            subscribed.fulfill()
        }
        .store(in: &tokens)

        wait(for: [subscribed], timeout: 0.1)

        let event = Counter.Event(id: "test", eventType: .increment)
        await stateMachine.send(event)
        await waitForExpectations(timeout: 0.1)
    }

    func testDoesNotNotifyOnNoStateChange() async {
        await stateMachine.send(Counter.Event(id: "test", eventType: .increment))
        let subscribed = expectation(description: "subscribed")
        let notified = expectation(description: "notified")
        notified.expectedFulfillmentCount = 1
        await stateMachine.listen { _ in
            notified.fulfill()
        }
        onSubscribe: {
            subscribed.fulfill()
        }
        .store(in: &tokens)

        wait(for: [subscribed], timeout: 0.1)

        let event = Counter.Event(id: "test", eventType: .adjustBy(0))
        await stateMachine.send(event)
        await waitForExpectations(timeout: 0.1)
    }

    func testDoesNotNotifyAfterUnsubscribe() async {
        await stateMachine.send(Counter.Event(id: "test", eventType: .increment))
        let subscribed = expectation(description: "subscribed")
        let notified = expectation(description: "notified")
        notified.expectedFulfillmentCount = 1
        let token = await stateMachine.listen { _ in
            notified.fulfill()
        }
        onSubscribe: {
            subscribed.fulfill()
        }

        wait(for: [subscribed], timeout: 0.1)

        await stateMachine.cancel(listenerToken: token)
        let event = Counter.Event(id: "test", eventType: .increment)
        await stateMachine.send(event)
        await waitForExpectations(timeout: 0.1)
    }

    func testDoesNotNotifyIfCancelledImmediately() async {
        await stateMachine.send(Counter.Event(id: "test", eventType: .increment))

        let notified = expectation(description: "notified")
        notified.expectedFulfillmentCount = 1
        let token = await stateMachine.listen({ state in
                notified.fulfill()
            },
            onSubscribe: nil
        )

        await stateMachine.cancel(listenerToken: token)
        let event = Counter.Event(id: "test", eventType: .increment)
        await stateMachine.send(event)
        await waitForExpectations(timeout: 0.1)
    }

}
