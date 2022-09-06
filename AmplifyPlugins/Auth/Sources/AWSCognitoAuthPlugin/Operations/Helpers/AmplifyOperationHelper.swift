//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

typealias AuthStateMachine = StateMachine<
    AuthState,
    AuthEnvironment>
typealias CredentialStoreStateMachine = StateMachine<
    CredentialStoreState,
    CredentialEnvironment>
