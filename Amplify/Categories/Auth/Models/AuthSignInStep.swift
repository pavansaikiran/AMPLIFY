//
// Copyright 2018-2020 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public typealias AdditionalInfo = [String: String]

/// Auth SignIn flow steps
///
///
public enum AuthSignInStep: Equatable {

    /// Auth step is SMS multi factor authentication.
    ///
    /// Confirmation code for the MFA will be send to the provided SMS.
    case confirmSignInWithSMSMFACode(AuthCodeDeliveryDetails, AdditionalInfo?)

    /// Auth step is in a custom challenge depending on the plugin.
    ///
    case confirmSignInWithCustomChallenge(AdditionalInfo?)

    /// Auth step required the user to give a new password.
    ///
    case confirmSignInWithNewPassword(AdditionalInfo?)

    /// Auth step required the user to change their password.
    ///
    case resetPassword(AdditionalInfo?)

    /// Auth step that required the user to be confirmed
    ///
    case confirmSignUp(AdditionalInfo?)

    /// There is no next step and the signIn flow is complete
    ///
    case done
}

// swiftlint:disable empty_enum_arguments
extension AuthSignInStep {
    public static func == (lhs: AuthSignInStep, rhs: AuthSignInStep) -> Bool {
        switch (lhs, rhs) {
        case (.done, .done):
            return true
        case (.confirmSignInWithSMSMFACode(_, _), .confirmSignInWithSMSMFACode(_, _)):
            return true
        case (.confirmSignInWithCustomChallenge(_), .confirmSignInWithCustomChallenge(_)):
            return true
        case (.confirmSignInWithNewPassword(_), .confirmSignInWithNewPassword(_)):
            return true
        case (.resetPassword(_), .resetPassword(_)):
            return true
        case (.confirmSignUp(_), .confirmSignUp(_)):
            return true
        default:
            return false
        }
    }
}
