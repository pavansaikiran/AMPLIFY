//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import AWSMobileClient

class AWSMobileClientAdapter: AWSMobileClientBehavior {

    let awsMobileClient: AWSMobileClient

    init(configuration: [String: Any]) {
        self.awsMobileClient = AWSMobileClient.init(configuration: configuration)
    }

    func initialize() throws {
        var mobileClientError: Error?
        awsMobileClient.initialize { _, error in
            mobileClientError = error
        }
        if let error = mobileClientError {
            throw AmplifyAuthError.configuration(AuthPluginErrorConstants.mobileClientInitializeError.errorDescription,
                                                 AuthPluginErrorConstants.mobileClientInitializeError.recoverySuggestion,
                                                 error)
        }
    }

    func signUp(username: String,
                password: String,
                userAttributes: [String: String] = [:],
                validationData: [String: String] = [:],
                clientMetaData: [String: String] = [:],
                completionHandler: @escaping ((SignUpResult?, Error?) -> Void)) {

        awsMobileClient.signUp(username: username,
                               password: password,
                               userAttributes: userAttributes,
                               validationData: validationData,
                               clientMetaData: clientMetaData,
                               completionHandler: completionHandler)
    }

    func confirmSignUp(username: String,
                       confirmationCode: String,
                       clientMetaData: [String: String] = [:],
                       completionHandler: @escaping ((SignUpResult?, Error?) -> Void)) {
        awsMobileClient.confirmSignUp(username: username,
                                      confirmationCode: confirmationCode,
                                      clientMetaData: clientMetaData,
                                      completionHandler: completionHandler)
    }

    func resendSignUpCode(username: String, completionHandler: @escaping ((SignUpResult?, Error?) -> Void)) {
        awsMobileClient.resendSignUpCode(username: username, completionHandler: completionHandler)
    }

    func signIn(username: String,
                password: String,
                validationData: [String: String]? = nil,
                completionHandler: @escaping ((SignInResult?, Error?) -> Void)) {
        awsMobileClient.signIn(username: username,
                               password: password,
                               validationData: validationData,
                               completionHandler: completionHandler)
    }

    func federatedSignIn(providerName: String, token: String,
                         federatedSignInOptions: FederatedSignInOptions,
                         completionHandler: @escaping ((UserState?, Error?) -> Void)) {
        awsMobileClient.federatedSignIn(providerName: providerName,
                                        token: token,
                                        federatedSignInOptions: federatedSignInOptions,
                                        completionHandler: completionHandler)
    }

    func showSignIn(navigationController: UINavigationController,
                    signInUIOptions: SignInUIOptions,
                    hostedUIOptions: HostedUIOptions?,
                    _ completionHandler: @escaping (UserState?, Error?) -> Void) {
        awsMobileClient.showSignIn(navigationController: navigationController,
                                   signInUIOptions: signInUIOptions,
                                   hostedUIOptions: hostedUIOptions,
                                   completionHandler)
    }

    func confirmSignIn(challengeResponse: String,
                       userAttributes: [String: String] = [:],
                       clientMetaData: [String: String] = [:],
                       completionHandler: @escaping ((SignInResult?, Error?) -> Void)) {
        awsMobileClient.confirmSignIn(challengeResponse: challengeResponse,
                                      userAttributes: userAttributes,
                                      clientMetaData: clientMetaData,
                                      completionHandler: completionHandler)
    }

    func signOut(options: SignOutOptions = SignOutOptions(), completionHandler: @escaping ((Error?) -> Void)) {
        awsMobileClient.signOut(options: options, completionHandler: completionHandler)
    }

    func username() -> String? {
        return awsMobileClient.username
    }

    func verifyUserAttribute(attributeName: String,
                             completionHandler: @escaping ((UserCodeDeliveryDetails?, Error?) -> Void)) {
        awsMobileClient.verifyUserAttribute(attributeName: attributeName,
                                            completionHandler: completionHandler)
    }

    func updateUserAttributes(attributeMap: [String: String],
                              completionHandler: @escaping (([UserCodeDeliveryDetails]?, Error?) -> Void)) {
        awsMobileClient.updateUserAttributes(attributeMap: attributeMap,
                                             completionHandler: completionHandler)
    }

    func getUserAttributes(completionHandler: @escaping (([String: String]?, Error?) -> Void)) {
        awsMobileClient.getUserAttributes(completionHandler: completionHandler)
    }

    func confirmUpdateUserAttributes(attributeName: String, code: String,
                                     completionHandler: @escaping ((Error?) -> Void)) {
        awsMobileClient.confirmUpdateUserAttributes(attributeName: attributeName,
                                                    code: code,
                                                    completionHandler: completionHandler)
    }

    func changePassword(currentPassword: String,
                        proposedPassword: String,
                        completionHandler: @escaping ((Error?) -> Void)) {
        awsMobileClient.changePassword(currentPassword: currentPassword,
                                       proposedPassword: proposedPassword,
                                       completionHandler: completionHandler)
    }

    func forgotPassword(username: String,
                        clientMetaData: [String: String],
                        completionHandler: @escaping ((ForgotPasswordResult?, Error?) -> Void)) {
        awsMobileClient.forgotPassword(username: username,
                                       clientMetaData: clientMetaData,
                                       completionHandler: completionHandler)
    }

    func confirmForgotPassword(username: String,
                               newPassword: String,
                               confirmationCode: String,
                               clientMetaData: [String: String],
                               completionHandler: @escaping ((ForgotPasswordResult?, Error?) -> Void)) {
        awsMobileClient.confirmForgotPassword(username: username,
                                              newPassword: newPassword,
                                              confirmationCode: confirmationCode,
                                              clientMetaData: clientMetaData,
                                              completionHandler: completionHandler)
    }
}
