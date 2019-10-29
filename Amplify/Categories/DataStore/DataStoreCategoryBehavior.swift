//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation

public typealias QueryCriteriaBuilder = () -> QueryCondition

public protocol DataStoreCategoryBehavior {

    func save<M: Model>(_ model: M, completion: DataStoreCallback<M>)

    func query<M: Model>(_ modelType: M.Type,
                         byId id: String,
                         completion: DataStoreCallback<M?>)

    func query<M: Model>(_ modelType: M.Type,
                         withCriteria criteria: QueryCriteriaBuilder?,
                         completion: DataStoreCallback<[M]>)

    func delete<M: Model>(_ model: M,
                          completion: DataStoreCallback<Bool>)

    func delete<M: Model>(_ modelType: M.Type,
                          withId id: String,
                          completion: DataStoreCallback<Void>?)

}
