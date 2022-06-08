//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import AWSPluginsCore
import AWSCognitoIdentityProvider

public class AWSAuthAttributeResendConfirmationCodeOperation: AmplifyOperation<
AuthAttributeResendConfirmationCodeRequest,
AuthCodeDeliveryDetails,
AuthError>, AuthAttributeResendConfirmationCodeOperation {
    
    typealias CognitoUserPoolFactory = () throws -> CognitoUserPoolBehavior
    
    private let authStateMachine: AuthStateMachine
    private let credentialStoreStateMachine: CredentialStoreStateMachine
    private let userPoolFactory: CognitoUserPoolFactory
    private var statelistenerToken: AuthStateMachineToken?
    private let fetchAuthSessionHelper: FetchAuthSessionOperationHelper
    
    init(_ request: AuthAttributeResendConfirmationCodeRequest,
         authStateMachine: AuthStateMachine,
         credentialStoreStateMachine: CredentialStoreStateMachine,
         userPoolFactory: @escaping CognitoUserPoolFactory,
         resultListener: ResultListener?)
    {
        self.authStateMachine = authStateMachine
        self.credentialStoreStateMachine = credentialStoreStateMachine
        self.userPoolFactory = userPoolFactory
        self.fetchAuthSessionHelper = FetchAuthSessionOperationHelper(
            authStateMachine: authStateMachine,
            credentialStoreStateMachine: credentialStoreStateMachine)
        super.init(categoryType: .auth,
                   eventName: HubPayload.EventName.Auth.attributeResendConfirmationCodeAPI,
                   request: request,
                   resultListener: resultListener)
    }
    
    override public func main() {
        if isCancelled {
            finish()
            return
        }
        
        fetchAuthSessionHelper.fetchSession { [weak self] result in
            switch result {
            case .success(let session):
                guard let cognitoTokenProvider = session as? AuthCognitoTokensProvider,
                      let tokens = try? cognitoTokenProvider.getCognitoTokens().get() else {
                    self?.dispatch(AuthError.unknown("Unable to fetch auth session", nil))
                    return
                }
                self?.initiateGettingVerificationCode(with: tokens.accessToken)
            case .failure(let error):
                self?.dispatch(error)
            }
        }
        
    }
    
    func initiateGettingVerificationCode(with accessToken: String) {
        
        let userPoolService: CognitoUserPoolBehavior?
        do {
            userPoolService = try userPoolFactory()
        }
        catch let error {
            let error = AuthError.configuration(
                "Unable to create a Swift SDK user pool service",
                AuthPluginErrorConstants.configurationError,
                error)
            self.dispatch(error)
            return
        }
        
        let clientMetaData = (request.options.pluginOptions
                              as? AWSAttributeResendConfirmationCodeOptions)?.metadata ?? [:]
        
        let input = GetUserAttributeVerificationCodeInput(
            accessToken: accessToken,
            attributeName: request.attributeKey.rawValue,
            clientMetadata: clientMetaData)
        
        userPoolService?.getUserAttributeVerificationCode(input: input) { [weak self] result in
            guard let self = self else { return }
            defer {
                self.finish()
            }
            if self.isCancelled {
                return
            }
            switch result {
            case .failure(let error):
                self.dispatch(error.authError)
            case .success(let result):
                guard let deliveryDetails = result.codeDeliveryDetails?.toAuthCodeDeliveryDetails() else {
                    let authError = AuthError.service("Unable to get Auth code delivery details",
                                                      AmplifyErrorMessages.shouldNotHappenReportBugToAWS(),
                                                      nil)
                    self.dispatch(authError)
                    return
                }
                self.dispatch(deliveryDetails)
            }
        }
    }
    
    private func dispatch(_ result: AuthCodeDeliveryDetails) {
        let result = OperationResult.success(result)
        dispatch(result: result)
        finish()
    }
    
    private func dispatch(_ error: AuthError) {
        let result = OperationResult.failure(error)
        dispatch(result: result)
        Amplify.log.error(error: error)
        finish()
    }
}
