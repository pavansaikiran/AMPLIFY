//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
import Amplify

public struct AWSAuthConfirmSignInWithOTPOptions {

    /// A map of custom key-value pairs that you can provide as input for any custom workflows that this action triggers.
    public let metadata: [String: String]?

    public init(metadata: [String: String]? = nil) {
        self.metadata = metadata
    }
}
