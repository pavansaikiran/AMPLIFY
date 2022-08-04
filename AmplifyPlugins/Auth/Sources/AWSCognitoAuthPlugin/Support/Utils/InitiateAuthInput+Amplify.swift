//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import AWSCognitoIdentityProvider

extension InitiateAuthInput {

    static func srpInput(username: String,
                         publicSRPAHexValue: String,
                         authFlowType: AuthFlowType,
                         clientMetadata: [String: String],
                         asfDeviceId: String,
                         deviceMetadata: DeviceMetadata,
                         environment: UserPoolEnvironment) -> InitiateAuthInput {
        var authParameters = [
            "USERNAME": username,
            "SRP_A": publicSRPAHexValue
        ]

        if authFlowType == .customWithSRP {
            authParameters["CHALLENGE_NAME"] = "SRP_A"
        }

        return buildInput(username: username,
                          authFlowType: authFlowType.getClientFlowType(),
                          authParameters: authParameters,
                          clientMetadata: clientMetadata,
                          asfDeviceId: asfDeviceId,
                          deviceMetadata: deviceMetadata,
                          environment: environment)
    }

    static func customAuth(username: String,
                           clientMetadata: [String: String],
                           asfDeviceId: String,
                           deviceMetadata: DeviceMetadata,
                           environment: UserPoolEnvironment) -> InitiateAuthInput {
        let authParameters = [
            "USERNAME": username
        ]

        return buildInput(username: username,
                          authFlowType: .customAuth,
                          authParameters: authParameters,
                          clientMetadata: clientMetadata,
                          asfDeviceId: asfDeviceId,
                          deviceMetadata: deviceMetadata,
                          environment: environment)
    }

    static func migrateAuth(username: String,
                            password: String,
                            clientMetadata: [String: String],
                            asfDeviceId: String,
                            environment: UserPoolEnvironment) -> InitiateAuthInput {
        let authParameters = [
            "USERNAME": username,
            "PASSWORD": password
        ]

        return buildInput(username: username,
                          authFlowType: .customAuth,
                          authParameters: authParameters,
                          clientMetadata: clientMetadata,
                          asfDeviceId: asfDeviceId,
                          deviceMetadata: .noData,
                          environment: environment)
    }

    static func buildInput(username: String,
                           authFlowType: CognitoIdentityProviderClientTypes.AuthFlowType,
                           authParameters: [String: String],
                           clientMetadata: [String: String],
                           asfDeviceId: String? = nil,
                           deviceMetadata: DeviceMetadata,
                           environment: UserPoolEnvironment) -> InitiateAuthInput {

        var authParameters = authParameters
        let configuration = environment.userPoolConfiguration
        let userPoolClientId = configuration.clientId

        if let clientSecret = configuration.clientSecret {
            let clientSecretHash = SRPSignInHelper.clientSecretHash(
                username: username,
                userPoolClientId: userPoolClientId,
                clientSecret: clientSecret
            )
            authParameters["SECRET_HASH"] = clientSecretHash
        }

        if case .metadata(let data) = deviceMetadata {
            authParameters["DEVICE_KEY"] = data.deviceKey
        }

        var userContextData: CognitoIdentityProviderClientTypes.UserContextDataType? = nil
        if let asfDeviceId = asfDeviceId,
           let encodedData = CognitoUserPoolASF.encodedContext(
            username: username,
            asfDeviceId: asfDeviceId,
            asfClient: environment.cognitoUserPoolASFFactory(),
            userPoolConfiguration: environment.userPoolConfiguration) {
            userContextData = .init(encodedData: encodedData)
        }

        return InitiateAuthInput(
            analyticsMetadata: nil,
            authFlow: authFlowType,
            authParameters: authParameters,
            clientId: userPoolClientId,
            clientMetadata: clientMetadata,
            userContextData: userContextData)
    }
}
