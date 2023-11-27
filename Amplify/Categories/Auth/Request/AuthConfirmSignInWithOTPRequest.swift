//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

/// Request to confirm sign in a user with OTP flow
public struct AuthConfirmSignInWithOTPRequest: AmplifyOperationRequest {

    /// The value of `challengeResponse`is the OTP that is received on the destination provided during sign in request
    public let challengeResponse: String

    /// Extra request options defined in `AuthConfirmSignInWithOTPRequest.Options`
    public var options: Options

    public init(challengeResponse: String, options: Options) {
        self.challengeResponse = challengeResponse
        self.options = options
    }
}

public extension AuthConfirmSignInWithOTPRequest {

    struct Options {

        /// Extra plugin specific options, only used in special circumstances when the existing options do not provide
        /// a way to utilize the underlying auth plugin functionality. See plugin documentation for expected
        /// key/values
        public let pluginOptions: Any?

        public init(pluginOptions: Any? = nil) {
            self.pluginOptions = pluginOptions
        }
    }
}
