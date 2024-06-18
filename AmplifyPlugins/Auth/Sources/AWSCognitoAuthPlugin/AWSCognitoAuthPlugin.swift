//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import AWSPluginsCore

import AWSClientRuntime // AWSClientRuntime.CredentialsProviding
import ClientRuntime // SdkHttpRequestBuilder
import InternalAmplifyCredentials // AmplifyAWSCredentialsProvider()
import AwsCommonRuntimeKit // CommonRuntimeKit.initialize()

public final class AWSCognitoAuthPlugin: AWSCognitoAuthPluginBehavior {

    var authEnvironment: AuthEnvironment!

    var authStateMachine: AuthStateMachine!

    var credentialStoreStateMachine: CredentialStoreStateMachine!

     /// A queue that regulates the execution of operations.
    var queue: OperationQueue!

    /// Configuration for the auth plugin
    var authConfiguration: AuthConfiguration!

    /// Handles different auth event send through hub
    var hubEventHandler: AuthHubEventBehavior!

    var analyticsHandler: UserPoolAnalyticsBehavior!

    var taskQueue: TaskQueue<Any>!

    var httpClientEngineProxy: HttpClientEngineProxy?

    /// The user network preferences for timeout and retry
    let networkPreferences: AWSCognitoNetworkPreferences?

    @_spi(InternalAmplifyConfiguration)
    internal(set) public var jsonConfiguration: JSONValue?

    /// The unique key of the plugin within the auth category.
    public var key: PluginKey {
        return "awsCognitoAuthPlugin"
    }

    /// Instantiates an instance of the AWSCognitoAuthPlugin.
    public init() {
        self.networkPreferences = nil
    }

    /// Instantiates an instance of the AWSCognitoAuthPlugin with custom network preferences
    /// - Parameters:
    ///   - networkPreferences: network preferences
    public init(networkPreferences: AWSCognitoNetworkPreferences) {
        self.networkPreferences = networkPreferences
    }
}

extension AWSCognitoAuthPlugin {
    public static func getUserPoolAccessToken() async throws -> String {
        let authSession = try await Amplify.Auth.fetchAuthSession()
        guard let tokenResult = getTokenString(from: authSession) else {
            let error = AuthError.unknown("Did not receive a valid response from fetchAuthSession for get token.")
            throw error
        }
        switch tokenResult {
        case .success(let token):
            return token
        case .failure(let error):
            throw error
        }
    }
    private static func getTokenString(from authSession: AuthSession) -> Result<String, AuthError>? {
        if let result = (authSession as? AuthCognitoTokensProvider)?.getCognitoTokens() {
            switch result {
            case .success(let tokens):
                return .success(tokens.accessToken)
            case .failure(let error):
                return .failure(error)
            }
        }
        return nil
    }

}

extension AWSCognitoAuthPlugin {
    public static func signRequest(_ urlRequest: URLRequest, 
                                   region: String) async throws -> URLRequest? {
        let requestBuilder = try createAppSyncSdkHttpRequestBuilder(
            urlRequest: urlRequest)

        guard let sdkHttpRequest = try await sigV4SignedRequest(
            requestBuilder: requestBuilder, 
            credentialsProvider: AmplifyAWSCredentialsProvider(),
            signingName: "appsync",
            signingRegion: region, // region
            date: Date()
        ) else {
            //throw APIError.unknown("Unable to sign request", "")
            return nil
        }

        return setHeaders(from: sdkHttpRequest, to: urlRequest)
    }

    // Helper

    public static func sigV4SignedRequest(requestBuilder: SdkHttpRequestBuilder,
                                          credentialsProvider: AWSClientRuntime.CredentialsProviding,
                                          signingName: Swift.String,
                                          signingRegion: Swift.String,
                                          date: ClientRuntime.Date) async throws -> SdkHttpRequest? {
        do {
            CommonRuntimeKit.initialize()
            let credentials = try await credentialsProvider.getCredentials()

            let flags = SigningFlags(useDoubleURIEncode: true,
                                     shouldNormalizeURIPath: true,
                                     omitSessionToken: false)
            let signedBodyHeader: AWSSignedBodyHeader = .none
            let signedBodyValue: AWSSignedBodyValue = .empty
            let signingConfig = AWSSigningConfig(credentials: credentials,
                                                 signedBodyHeader: signedBodyHeader,
                                                 signedBodyValue: signedBodyValue,
                                                 flags: flags,
                                                 date: date,
                                                 service: signingName,
                                                 region: signingRegion,
                                                 signatureType: .requestHeaders,
                                                 signingAlgorithm: .sigv4)

            let httpRequest = await AWSSigV4Signer.sigV4SignedRequest(
                requestBuilder: requestBuilder,
                signingConfig: signingConfig
            )
            return httpRequest
        } catch let error {
            throw AuthError.unknown("Unable to sign request", error)
        }
    }

    static func setHeaders(from sdkRequest: SdkHttpRequest, to urlRequest: URLRequest) -> URLRequest {
        var urlRequest = urlRequest
        for header in sdkRequest.headers.headers {
            urlRequest.setValue(header.value.joined(separator: ","), forHTTPHeaderField: header.name)
        }
        return urlRequest
    }

    static func createAppSyncSdkHttpRequestBuilder(urlRequest: URLRequest) throws -> SdkHttpRequestBuilder {

        guard let url = urlRequest.url else {
            throw AuthError.unknown("Could not get url from mutable request", nil)
        }
        guard let host = url.host else {
            throw AuthError.unknown("Could not get host from mutable request", nil)
        }
        var headers = urlRequest.allHTTPHeaderFields ?? [:]
        headers.updateValue(host, forKey: "host")

        let httpMethod = (urlRequest.httpMethod?.uppercased())
            .flatMap(HttpMethodType.init(rawValue:)) ?? .get

        let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?
            .map { ClientRuntime.SDKURLQueryItem(name: $0.name, value: $0.value)} ?? []

        let requestBuilder = SdkHttpRequestBuilder()
            .withHost(host)
            .withPath(url.path)
            .withQueryItems(queryItems)
            .withMethod(httpMethod)
            .withPort(443)
            .withProtocol(.https)
            .withHeaders(.init(headers))
            .withBody(.data(urlRequest.httpBody))

        return requestBuilder
    }
}
