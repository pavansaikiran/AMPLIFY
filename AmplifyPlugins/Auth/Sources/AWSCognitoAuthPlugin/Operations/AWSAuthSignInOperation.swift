//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify

import ClientRuntime
import AWSCognitoIdentityProvider

public typealias AmplifySignInOperation = AmplifyOperation<
    AuthSignInRequest,
    AuthSignInResult,
    AuthError>

public class AWSAuthSignInOperation: AmplifySignInOperation,
                                     AuthSignInOperation {

    let authStateMachine: AuthStateMachine

    var stateMachineToken: AuthStateMachineToken?

    init(_ request: AuthSignInRequest,
         authStateMachine: AuthStateMachine,
         resultListener: ResultListener?) {

        self.authStateMachine = authStateMachine
        super.init(categoryType: .auth,
                   eventName: HubPayload.EventName.Auth.signInAPI,
                   request: request,
                   resultListener: resultListener)
    }

    override public func main() {
        if isCancelled {
            finish()
            return
        }
        didConfigure {
            self.isCurrentStateValid { result in
                switch result {
                case .success:
                    self.doSignIn()
                case .failure(let error):
                    self.dispatch(error)
                    self.finish()
                }
            }
        }
    }

    func didConfigure(completion: @escaping () -> Void) {
        stateMachineToken = authStateMachine.listen({ state in
            guard case .configured = state else { return }
            if let statemachineToken = self.stateMachineToken {
                self.authStateMachine.cancel(listenerToken: statemachineToken)
            }
            completion()
        }, onSubscribe: {})
    }

    func isCurrentStateValid(completion: @escaping ((Result<Void, AuthError>) -> Void)) {
        stateMachineToken = authStateMachine.listen({ state in
            guard case .configured(let authenticationState, _) = state else {
                return
            }

            switch authenticationState {
            case .signedIn:
                let error = AuthError.invalidState(
                    "There is already a user in signedIn state. SignOut the user first before calling signIn",
                    AuthPluginErrorConstants.invalidStateError, nil)
                if let statemachineToken = self.stateMachineToken {
                    self.authStateMachine.cancel(listenerToken: statemachineToken)
                }
                completion(.failure(error))

            case .signedOut:
                if let statemachineToken = self.stateMachineToken {
                    self.authStateMachine.cancel(listenerToken: statemachineToken)
                }
                completion(.success(Void()))

            case .signingUp:
                self.sendCancelSignUpEvent()
            default: break
            }
        }, onSubscribe: {})
    }

    func doSignIn() {
        if isCancelled {
            finish()
            return
        }

        var token: AuthStateMachine.StateChangeListenerToken?
        token = authStateMachine.listen { [weak self] in
            guard let self = self else {
                return
            }
            guard case .configured(let authNState,
                                   let authZState) = $0 else { return }

            switch authNState {

            case .signedIn:
                if case .sessionEstablished = authZState {
                    self.dispatch(AuthSignInResult(nextStep: .done))
                    self.cancelToken(token)
                    self.finish()
                } else if case .error(let error) = authZState {
                    self.dispatch(AuthError.unknown("Sign in reached an error state", error))
                    self.cancelToken(token)
                    self.finish()
                }

            case .error(let error):
                self.dispatch(AuthError.unknown("Sign in reached an error state", error))
                self.cancelToken(token)
                self.finish()

            case .signingIn(let signInState):
                guard let result = UserPoolSignInHelper.checkNextStep(signInState) else {
                    return
                }
                self.dispatch(result: result)
                self.cancelToken(token)
                self.finish()
            default:
                break
            }
        } onSubscribe: { self.sendSignInEvent() }
    }

    private func sendSignInEvent() {
        let signInData = SignInEventData(
            username: request.username,
            password: request.password,
            clientMetadata: clientMetadata(),
            signInMethod: .apiBased(authFlowType())
        )
        let event = AuthenticationEvent.init(eventType: .signInRequested(signInData))
        authStateMachine.send(event)
    }

    private func sendCancelSignUpEvent() {
        let event = AuthenticationEvent(eventType: .cancelSignUp)
        authStateMachine.send(event)
    }

    private func dispatch(_ result: AuthSignInResult) {
        let asyncEvent = AWSAuthSignInOperation.OperationResult.success(result)
        dispatch(result: asyncEvent)
    }

    private func dispatch(_ error: AuthError) {
        let asyncEvent = AWSAuthSignInOperation.OperationResult.failure(error)
        dispatch(result: asyncEvent)
    }

    private func cancelToken(_ token: AuthStateMachineToken?) {
        if let token = token {
            authStateMachine.cancel(listenerToken: token)
        }
    }

    private func authFlowType() -> AuthFlowType {
        (request.options.pluginOptions as? AWSAuthSignInOptions)?.authFlowType ?? .unknown
    }

    private func clientMetadata() -> [String: String] {
        (request.options.pluginOptions as? AWSAuthSignInOptions)?.metadata ?? [:]
    }
}
