//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

struct CredentialEnvironment: Environment {
    let authConfiguration: AuthConfiguration
    let credentialStoreEnvironment: CredentialStoreEnvironment
}

protocol CredentialStoreEnvironment: Environment {
    typealias AmplifyAuthCredentialStoreFactory = () -> AmplifyAuthCredentialStoreBehavior
    typealias CredentialStoreFactory = (_ service: String) -> CredentialStoreBehavior

    var amplifyCredentialStoreFactory: AmplifyAuthCredentialStoreFactory { get }
    var legacyCredentialStoreFactory: CredentialStoreFactory { get }
    var eventIDFactory: EventIDFactory { get }
}

struct BasicCredentialStoreEnvironment: CredentialStoreEnvironment {

    typealias AmplifyAuthCredentialStoreFactory = () -> AmplifyAuthCredentialStoreBehavior
    typealias CredentialStoreFactory = (_ service: String) -> CredentialStoreBehavior

    // Required
    let amplifyCredentialStoreFactory: AmplifyAuthCredentialStoreFactory
    let legacyCredentialStoreFactory: CredentialStoreFactory

    // Optional
    let eventIDFactory: EventIDFactory

    init(amplifyCredentialStoreFactory: @escaping AmplifyAuthCredentialStoreFactory,
         legacyCredentialStoreFactory: @escaping CredentialStoreFactory,
         eventIDFactory: @escaping EventIDFactory = UUIDFactory.factory) {
        self.amplifyCredentialStoreFactory = amplifyCredentialStoreFactory
        self.legacyCredentialStoreFactory = legacyCredentialStoreFactory
        self.eventIDFactory = eventIDFactory
    }
}
