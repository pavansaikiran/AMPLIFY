//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import ClientRuntime

struct FoundationHTTPClientError: AmplifyError {
    let errorDescription: ErrorDescription
    let recoverySuggestion: RecoverySuggestion
    let underlyingError: Error?

    // protocol requirement
    init(
        errorDescription: ErrorDescription,
        recoverySuggestion: RecoverySuggestion,
        error: Error
    ) {
        self.errorDescription = errorDescription
        self.recoverySuggestion = recoverySuggestion
        self.underlyingError = error
    }
}

extension FoundationHTTPClientError {
    init(
        errorDescription: ErrorDescription,
        recoverySuggestion: RecoverySuggestion,
        error: Error?
    ) {
        self.errorDescription = errorDescription
        self.recoverySuggestion = recoverySuggestion
        self.underlyingError = error
    }

    static func invalidRequestURL(sdkRequest: ClientRuntime.SdkHttpRequest) -> Self {
        .init(
            errorDescription: """
            The SdkHttpRequest generated by ClientRuntime doesn't include a valid URL
            - \(sdkRequest)
            """,
            recoverySuggestion: """
            Please open an issue at https://github.com/aws-amplify/amplify-swift
            with the contents of this error message.
            """,
            error: nil
        )
    }

    static func invalidURLResponse(urlRequest: URLResponse) -> Self {
        .init(
            errorDescription: """
            The URLResponse received is not an HTTPURLResponse
            - \(urlRequest)
            """,
            recoverySuggestion: """
            Please open an issue at https://github.com/aws-amplify/amplify-swift
            with the contents of this error message.
            """,
            error: nil
        )
    }

    static func unexpectedStatusCode(statusCode: Int) -> Self {
        .init(
            errorDescription: """
            The status code received isn't a valid `HttpStatusCode` value.
            - status code: \(statusCode)
            """,
            recoverySuggestion: """
            Please open an issue at https://github.com/aws-amplify/amplify-swift
            with the contents of this error message.
            """,
            error: nil
        )
    }
}
