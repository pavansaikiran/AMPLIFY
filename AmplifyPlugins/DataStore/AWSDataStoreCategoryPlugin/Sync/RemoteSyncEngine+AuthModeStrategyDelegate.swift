//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Combine
import Foundation
import AWSPluginsCore

extension RemoteSyncEngine: AuthModeStrategyDelegate {
    func isUserLoggedIn() -> Bool {
        // if OIDC is used as authentication provider
        // use `getLatestAuthToken`
        var isLoggedInWithOIDC = false

        if let authProviderFactory = api as? APICategoryAuthProviderFactoryBehavior,
           let oidcAuthProvider = authProviderFactory.apiAuthProviderFactory().oidcAuthProvider() {
            switch oidcAuthProvider.getLatestAuthToken() {
            case .failure:
                isLoggedInWithOIDC = false
            case .success:
                isLoggedInWithOIDC = true
            }

            return isLoggedInWithOIDC
        }

        guard let auth = auth else {
            return false
        }

        // Note: blocking is not recommended
        let group = DispatchGroup()
        var isSignedIn = false

        group.enter()
        auth.getCurrentUser { result in
            if case .success(let user) = result {
                isSignedIn = user != nil
            }
            group.leave()
        }
        group.wait()

        return isSignedIn
    }
}
