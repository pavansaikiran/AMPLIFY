//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import AWSPluginsCore
import ClientRuntime
import AWSCognitoIdentityProvider

protocol AuthUpdateMFAPreferenceTask: AmplifyAuthTask where Request == UpdateMFAPreferenceRequest,
                                                            Success == Void,
                                                            Failure == AuthError {}

public extension HubPayload.EventName.Auth {
    /// eventName for HubPayloads emitted by this operation
    static let updateMFAPreferenceAPI = "Auth.updateMFAPreferenceAPI"
}

class UpdateMFAPreferenceTask: AuthUpdateMFAPreferenceTask, DefaultLogger {

    typealias CognitoUserPoolFactory = () throws -> CognitoUserPoolBehavior

    private let request: UpdateMFAPreferenceRequest
    private let authStateMachine: AuthStateMachine
    private let userPoolFactory: CognitoUserPoolFactory
    private let taskHelper: AWSAuthTaskHelper

    var eventName: HubPayloadEventName {
        HubPayload.EventName.Auth.updateMFAPreferenceAPI
    }

    init(_ request: UpdateMFAPreferenceRequest,
         authStateMachine: AuthStateMachine,
         userPoolFactory: @escaping CognitoUserPoolFactory) {
        self.request = request
        self.authStateMachine = authStateMachine
        self.userPoolFactory = userPoolFactory
        self.taskHelper = AWSAuthTaskHelper(authStateMachine: authStateMachine)
    }

    func execute() async throws {
        do {
            await taskHelper.didStateMachineConfigured()
            let accessToken = try await taskHelper.getAccessToken()
            return try await updateMFAPreference(with: accessToken)
        } catch let error as AuthErrorConvertible {
            throw error.authError
        } catch let error as AuthError {
            throw error
        } catch let error {
            throw AuthError.unknown("Unable to execute auth task", error)
        }
    }

    func updateMFAPreference(with accessToken: String) async throws {
        let userPoolService = try userPoolFactory()
        let input = SetUserMFAPreferenceInput(
            accessToken: accessToken,
            smsMfaSettings: request.smsPreference?.smsSetting,
            softwareTokenMfaSettings: request.totpPreference?.softwareTokenSetting)
        _ = try await userPoolService.setUserMFAPreference(input: input)
    }
}
