//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Combine

@available(iOS 13.0, *)
struct DataStorePublisher: ModelSubcriptionBehavior {

    private let subject = PassthroughSubject<MutationEvent, DataStoreError>()

    func publisher(for modelName: ModelName) -> AnyPublisher<MutationEvent, DataStoreError> {
        return subject
            .filter { $0.modelName == modelName }
            .eraseToAnyPublisher()
    }

    func publisher() -> AnyPublisher<MutationEvent, DataStoreError> {
        return subject.eraseToAnyPublisher()
    }

    func send(input: MutationEvent) {
        subject.send(input)
    }

    func send(dataStoreError: DataStoreError) {
        subject.send(completion: .failure(dataStoreError))
    }

    func sendFinished() {
        subject.send(completion: .finished)
    }
}

protocol ModelSubcriptionBehavior {

    @available(iOS 13.0, *)
    func publisher(for modelName: ModelName) -> AnyPublisher<MutationEvent, DataStoreError>

    @available(iOS 13.0, *)
    func publisher() -> AnyPublisher<MutationEvent, DataStoreError>

    func send(input: MutationEvent)

    func send(dataStoreError: DataStoreError)

    func sendFinished()
}
