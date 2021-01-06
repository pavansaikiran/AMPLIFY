//
// Copyright 2018-2021 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import CoreGraphics

public struct Selection {
    public let boundingBox: CGRect
    public let polygon: Polygon
    public let isSelected: Bool

    public init(boundingBox: CGRect, polygon: Polygon, isSelected: Bool) {
        self.boundingBox = boundingBox
        self.polygon = polygon
        self.isSelected = isSelected
    }
}
