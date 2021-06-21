//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import XCTest
import Amplify
@testable import AWSAPICategoryPlugin

class GraphQLOperationRequestValidateTests: XCTestCase {

    let testApiName = "testApiName"
    let testDocument = "testDocument"

    func testGraphQLOperationRequestValidate() throws {
        let graphQLOperationRequest = GraphQLOperationRequest(apiName: testApiName,
                                                     operationType: .mutation,
                                                     document: testDocument,
                                                     responseType: String.self,
                                                     options: nil)
        XCTAssertNoThrow(try graphQLOperationRequest.validate())
    }
}
