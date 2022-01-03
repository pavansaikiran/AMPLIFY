//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
#if COCOAPODS
import AWSMobileClient
#else
import AWSMobileClientXCF
#endif

extension AuthenticationProviderAdapter {

    func deleteUser(request: AuthDeleteUserRequest, completionHandler: @escaping (Result<Void, AuthError>) -> Void) {
        // By default, ASWMobileClient calls signOut internally during deleteUser.
        // For Amplify, we instead call Amplify's signOut function, which contains some higher level logic.
        awsMobileClient.deleteUser(signOut: false) { [weak self] error in
            guard let error = error else {
                let signOutOptions = AuthSignOutRequest.Options(globalSignOut: true)
                let signOutRequest = AuthSignOutRequest(options: signOutOptions)
                self?.signOut(request: signOutRequest) { result in
                    switch result {
                    case .success:
                        completionHandler(.success(()))
                        return
                    case .failure(let error):
                        completionHandler(.failure(AuthErrorHelper.toAuthError(error)))
                        return
                    }
                }
                return
            }
            if case .notSignedIn = error as? AWSMobileClientError {
                let authError = AuthError.signedOut(AuthPluginErrorConstants.deleteUserSignOutError.errorDescription,
                                                    AuthPluginErrorConstants.deleteUserSignOutError.recoverySuggestion,
                                                    error)
                completionHandler(.failure(authError))
                return
            }
            completionHandler(.failure(AuthErrorHelper.toAuthError(error)))
        }
    }
}
