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
    public static func signRequest(_ urlRequest: URLRequest, region: String) async throws -> URLRequest? {
        let requestBuilder = try createAppSyncSdkHttpRequestBuilder(
            urlRequest: urlRequest,
            headers: urlRequest.allHTTPHeaderFields,
            body: urlRequest.httpBody)

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
    public struct IAM {
        let host: String
        let authToken: String
        let securityToken: String
        let amzDate: String
    }
    
    public static func getAuthHeader(_ endpoint: URL, with payload: Data, region: String) async throws -> (String, String, String, String)? {
        guard let host = endpoint.host else {
            return nil
        }

        /// The process of getting the auth header for an IAM based authentication request is as follows:
        ///
        /// 1. A request is created with the IAM based auth headers (date,  accept, content encoding, content type, and
        /// additional headers.
        let requestBuilder = SdkHttpRequestBuilder()
            .withHost(host)
            .withPath(endpoint.path)
            .withMethod(.post)
            .withPort(443)
            .withProtocol(.https)
            .withHeader(name: "accept", value: "application/json, text/javascript")
            .withHeader(name: "content-encoding", value: "amz-1.0")
            .withHeader(name: "Content-Type", value: "application/json; charset=UTF-8")
            .withHeader(name: "host", value: host)
            .withBody(.data(payload))

        /// 2. The request is SigV4 signed by using all the available headers on the request. By signing the request, the signature is added to
        /// the request headers as authorization and security token.
        do {
            guard let urlRequest = try await sigV4SignedRequest(
                requestBuilder: requestBuilder, 
                credentialsProvider: AmplifyAWSCredentialsProvider(),
                signingName: "appsync",
                signingRegion: region, // region
                date: Date())
            else {
                print("Unable to sign request")
                return nil
            }

            // TODO: Using long lived credentials without getting a session with security token will fail
            // since the session token does not exist on the signed request, and is an empty string.
            // Once Amplify.Auth is ready to be integrated, this code path needs to be re-tested.
            let headers = urlRequest.headers.headers.reduce([String: String]()) { partialResult, header in
                switch header.name.lowercased() {
                case "authorization", "x-amz-date", "x-amz-security-token":
                    guard let headerValue = header.value.first else {
                        return partialResult
                    }
                    return partialResult.merging([header.name.lowercased(): headerValue]) { $1 }
                default:
                    return partialResult
                }
            }

            return (
                host,
                headers["authorization"] ?? "",
                headers["x-amz-security-token"] ?? "",
                headers["x-amz-date"] ?? ""
            )
        } catch {
            print("Unable to sign request")
            return nil
        }
    }


    // Helper

    public static func sigV4SignedRequest(requestBuilder: SdkHttpRequestBuilder,
                                   credentialsProvider: AWSClientRuntime.CredentialsProviding,
                                   signingName: Swift.String,
                                   signingRegion: Swift.String,
                                   date: ClientRuntime.Date) async throws -> SdkHttpRequest? {
        do {
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

    static func createAppSyncSdkHttpRequestBuilder(urlRequest: URLRequest,
                                            headers: [String : String]?,
                                            body: Data?) throws -> SdkHttpRequestBuilder {

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
