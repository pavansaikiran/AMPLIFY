//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import UIKit
@testable import Amplify
@testable import AWSPredictionsPlugin
@testable import AWSRekognition
import XCTest

class IdentifyBasicIntegrationTests: AWSPredictionsPluginTestBase {

    private func imageURL(for resource: String) throws -> URL {
        try XCTUnwrap(
            Bundle(for: type(of: self))
                .url(forResource: resource, withExtension: "jpg")
        )
    }

    /// Given: An Image
    /// When: Image is sent to Rekognition
    /// Then: The operation completes successfully
    func testIdentifyLabels() async throws {
        let image = try imageURL(for: "testImageLabels")
        let result = try await Amplify.Predictions
            .identify(.labels(type: .labels), in: image)

        let electronicsLabel = try XCTUnwrap(
            result.labels.first(where: { $0.name == "Electronics" })?.metadata
        )
        let isConfidentImageContainsElectronics = electronicsLabel.confidence >= 99
        XCTAssertNotNil(result)
    }

    func testIdentifyModerationLabels() async throws {
        let image = try imageURL(for: "testImageLabels")
        let result = try await Amplify.Predictions
            .identify(.labels(type: .moderation), in: image)

        XCTAssert(result.unsafeContent == false)
    }

    func testIdentifyAllLabels() async throws {
        let image = try imageURL(for: "testImageLabels")
        let result = try await Amplify.Predictions
            .identify(.labels(type: .all), in: image)

        let imageContainsElectronics = result.labels.contains(
            where: { $0.name == "Electronics" }
        )
        XCTAssert(imageContainsElectronics)
    }

    func testIdentifyCelebrities() async throws {
        let image = try imageURL(for: "testImageCeleb")
        let result = try await Amplify.Predictions.identify(.celebrities, in: image)
        let imageContainsBillClinton = result.celebrities.contains(
            where: { $0.metadata.name == "Bill Clinton" }
        )
        XCTAssert(imageContainsBillClinton)
    }

    func testIdentifyEntities() async throws {
        let image = try imageURL(for: "testImageEntities")
        let result = try await Amplify.Predictions.identify(.entities, in: image)
        let imageContainsTwoEntities = result.entities.count == 2
        XCTAssert(imageContainsTwoEntities)
    }

    func testIdentifyTextPlain() async throws {
        let image = try imageURL(for: "testImageText")
        let result = try await Amplify.Predictions
            .identify(.textInDocument(textFormatType: .plain), in: image)

        let foundWords = Set(result.words.map(\.text))
        let expectedWordsSample = Set(["ANAGRAM", "BETTER", "IDEAS", "THIS"])
        let didFindExpectedWords = expectedWordsSample.subtracting(foundWords).isEmpty
        XCTAssert(didFindExpectedWords)
    }

    /// Given:
    /// - An Image with plain text, form and table
    /// When:
    /// - Image is sent to Textract
    /// Then:
    /// - The operation completes successfully
    /// - fullText from returned data is not empty
    /// - keyValues from returned data is not empty
    /// - tables from returned data is not empty
    func testIdentifyTextAll() async throws {
        let image = try imageURL(for: "testImageTextAll")
        let result = try await Amplify.Predictions
            .identify(.textInDocument(textFormatType: .all), in: image)

        XCTAssertNotNil(result)
        XCTAssertFalse(result.fullText.isEmpty)
        XCTAssertFalse(result.words.isEmpty)
        XCTAssertEqual(result.words.count, 55)
        XCTAssertFalse(result.rawLineText.isEmpty)
        XCTAssertEqual(result.rawLineText.count, 23)
        XCTAssertFalse(result.identifiedLines.isEmpty)
        XCTAssertEqual(result.identifiedLines.count, 23)
        XCTAssertFalse(result.tables.isEmpty)
        XCTAssertEqual(result.tables.count, 1)
        XCTAssertFalse(result.keyValues.isEmpty)
        XCTAssertEqual(result.keyValues.count, 4)

    }

    /// Given:
    /// - An Image with plain text and form
    /// When:
    /// - Image is sent to Textract
    /// Then:
    /// - The operation completes successfully
    /// - fullText from returned data is not empty
    /// - keyValues from returned data is not empty
    func testIdentifyTextForms() async throws {
        let image = try imageURL(for: "testImageTextForms")
        let result = try await Amplify.Predictions
            .identify(.textInDocument(textFormatType: .form), in: image)

        XCTAssertNotNil(result)
        XCTAssertFalse(result.fullText.isEmpty)
        XCTAssertFalse(result.words.isEmpty)
        XCTAssertEqual(result.words.count, 30)
        XCTAssertFalse(result.rawLineText.isEmpty)
        XCTAssertEqual(result.rawLineText.count, 17)
        XCTAssertFalse(result.identifiedLines.isEmpty)
        XCTAssertEqual(result.identifiedLines.count, 17)
        XCTAssertFalse(result.keyValues.isEmpty)
        XCTAssertEqual(result.keyValues.count, 7)
    }

    /// Given:
    /// - An Image with plain text and table
    /// When:
    /// - Image is sent to Textract
    /// Then:
    /// - The operation completes successfully
    /// - fullText from returned data is not empty
    /// - tables from returned data is not empty
    func testIdentifyTextTables() async throws {
        let image = try imageURL(for: "testImageTextWithTables")
        let result = try await Amplify.Predictions
            .identify(.textInDocument(textFormatType: .table), in: image)

        XCTAssertNotNil(result)
        XCTAssertFalse(result.fullText.isEmpty)
        XCTAssertFalse(result.words.isEmpty)
        XCTAssertEqual(result.words.count, 5)
        XCTAssertFalse(result.rawLineText.isEmpty)
        XCTAssertEqual(result.rawLineText.count, 3)
        XCTAssertFalse(result.identifiedLines.isEmpty)
        XCTAssertEqual(result.identifiedLines.count, 3)
        XCTAssertFalse(result.tables.isEmpty)
        XCTAssertEqual(result.tables.count, 1)
        XCTAssertFalse(result.tables[0].cells.isEmpty)
        XCTAssertEqual(result.tables[0].cells.count, 3)
        XCTAssertEqual(result.tables[0].cells[0].rowIndex, 1)
        XCTAssertEqual(result.tables[0].cells[0].columnIndex, 1)
        XCTAssertEqual(result.tables[0].cells[0].text, "Upper left")
        XCTAssertEqual(result.tables[0].cells[1].rowIndex, 2)
        XCTAssertEqual(result.tables[0].cells[1].columnIndex, 2)
        XCTAssertEqual(result.tables[0].cells[1].text, "Middle")
        XCTAssertEqual(result.tables[0].cells[2].rowIndex, 3)
        XCTAssertEqual(result.tables[0].cells[2].columnIndex, 3)
        XCTAssertEqual(result.tables[0].cells[2].text, "Bottom right")
    }
}
