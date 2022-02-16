//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

struct UserPoolConfigurationData: Equatable {

    let poolId: String
    let clientId: String
    let region: String
    let clientSecret: String?
    let pinpointAppId: String?
    let hostedUIConfig: HostedUIConfigurationData?

    init(poolId: String,
                clientId: String,
                region: String,
                clientSecret: String? = nil,
                pinpointAppId: String? = nil,
                hostedUIConfig: HostedUIConfigurationData? = nil)
    {
        self.poolId = poolId
        self.clientId = clientId
        self.region = region
        self.clientSecret = clientSecret
        self.pinpointAppId = pinpointAppId
        self.hostedUIConfig = hostedUIConfig
    }

    /// Amazon Cognito user pool: cognito-idp.<region>.amazonaws.com/<YOUR_USER_POOL_ID>,
    /// for example, cognito-idp.us-east-1.amazonaws.com/us-east-1_123456789.
    func getIdentityProviderName() -> String {
        return "cognito-idp.\(region).amazonaws.com/\(poolId)"
    }

}

extension UserPoolConfigurationData: Codable { }

extension UserPoolConfigurationData: CustomDebugDictionaryConvertible {
    var debugDictionary: [String: Any] {
        [
            "poolId": poolId.masked(interiorCount: 4, retainingCount: 4),
            "clientId": clientId.masked(interiorCount: 4, retainingCount: 4),
            "region": region.masked(interiorCount: 4, retainingCount: 4),
            "clientSecret": clientSecret.masked(interiorCount: 4),
            "pinpointAppId": pinpointAppId.masked(interiorCount: 4, retainingCount: 4),
            "hostedUI": hostedUIConfig?.debugDescription ?? "NA"
        ]
    }
}

extension UserPoolConfigurationData: CustomDebugStringConvertible {
    var debugDescription: String {
        debugDictionary.debugDescription
    }
}
