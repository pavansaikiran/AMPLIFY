//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

public protocol DataStoreCategoryPlugin: Plugin, DataStoreCategoryBehavior { }

public extension DataStoreCategoryPlugin {
    var categoryType: CategoryType {
        return .dataStore
    }
}
