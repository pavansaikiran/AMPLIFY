//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import AWSS3
import AWSMobileClient

// TODO: thread safety: everything has to be locked down
// TODO verify no retain cycle
public class AWSS3StorageGetURLOperation: AmplifyOperation<StorageGetURLRequest, Void, URL, StorageError>,
    StorageGetURLOperation {

    let storageService: AWSS3StorageServiceBehaviour
    let authService: AWSAuthServiceBehavior

    init(_ request: StorageGetURLRequest,
         storageService: AWSS3StorageServiceBehaviour,
         authService: AWSAuthServiceBehavior,
         onEvent: EventListener?) {

        self.storageService = storageService
        self.authService = authService
        super.init(categoryType: .storage, request: request, onEvent: onEvent)
    }

    override public func cancel() {
        super.cancel()
    }

    override public func main() {
        if isCancelled {
            finish()
            return
        }

        if let error = request.validate() {
            dispatch(error)
            finish()
            return
        }

        let identityIdResult = authService.getIdentityId()
        guard case let .success(identityId) = identityIdResult else {
            if case let .failure(error) = identityIdResult {
                dispatch(StorageError.authError(error.errorDescription, error.recoverySuggestion))
            }

            finish()
            return
        }

        let serviceKey = StorageRequestUtils.getServiceKey(accessLevel: request.options.accessLevel,
                                                           identityId: identityId,
                                                           key: request.key,
                                                           targetIdentityId: request.options.targetIdentityId)

        if isCancelled {
            finish()
            return
        }

        storageService.getPreSignedURL(serviceKey: serviceKey, expires: request.options.expires) { [weak self] event in
            self?.onEventListener(event: event)
        }
    }

    private func onEventListener(event: StorageEvent<Void, Void, URL, StorageError>) {
        switch event {
        case .completed(let result):
            dispatch(result)
            finish()
        case .failed(let error):
            dispatch(error)
            finish()
        default:
            break
        }
    }

    private func dispatch(_ result: URL) {
        let asyncEvent = AsyncEvent<Void, URL, StorageError>.completed(result)
        dispatch(event: asyncEvent)
    }

    private func dispatch(_ error: StorageError) {
        let asyncEvent = AsyncEvent<Void, URL, StorageError>.failed(error)
        dispatch(event: asyncEvent)
    }
}
