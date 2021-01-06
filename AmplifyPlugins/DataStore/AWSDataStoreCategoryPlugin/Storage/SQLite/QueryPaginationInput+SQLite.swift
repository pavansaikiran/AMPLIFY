//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify

extension QueryPaginationInput {

    var sqlStatement: String {
        let offset = page * limit
        return "limit \(limit) offset \(offset)"
    }

}
