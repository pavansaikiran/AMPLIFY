//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify

class IdentifyMultiService: MultiServiceBehavior {

    typealias Event = PredictionsEvent<IdentifyResult, PredictionsError>
    typealias IdentifyEventHandler = (Event) -> Void

    weak var coreMLService: CoreMLPredictionBehavior?
    weak var predictionsService: AWSPredictionsService?
    var request: PredictionsIdentifyRequest!

    init(coreMLService: CoreMLPredictionBehavior?,
         predictionsService: AWSPredictionsService?) {
        self.coreMLService = coreMLService
        self.predictionsService = predictionsService
    }

    func setRequest(_ request: PredictionsIdentifyRequest) {
        self.request = request
    }

    func fetchOnlineResult(callback: @escaping IdentifyEventHandler) {
        guard let onlineService = predictionsService else {
            let message = IdentifyMultiServiceErrorMessage.onlineIdentifyServiceNotAvailable.errorDescription
            let recoveryMessage = IdentifyMultiServiceErrorMessage.onlineIdentifyServiceNotAvailable.recoverySuggestion
            let predictionError = PredictionsError.service(message, recoveryMessage, nil)
            callback(.failed(predictionError))
            return
        }

        switch request.identifyType {
        case .detectCelebrity:
            onlineService.detectCelebrities(image: request.image, onEvent: callback)
        case .detectText(let formatType):
            onlineService.detectText(image: request.image, format: formatType, onEvent: callback)
        case .detectLabels(let labelType):
            onlineService.detectLabels(image: request.image, type: labelType, onEvent: callback)
        case .detectEntities:
            onlineService.detectEntities(image: request.image, onEvent: callback)
        }
    }

    func fetchOfflineResult(callback: @escaping IdentifyEventHandler) {
        guard let offlineService = coreMLService else {
            let message = IdentifyMultiServiceErrorMessage.offlineIdentifyServiceNotAvailable.errorDescription
            let recoveryMessage = IdentifyMultiServiceErrorMessage.offlineIdentifyServiceNotAvailable.recoverySuggestion
            let predictionError = PredictionsError.service(message, recoveryMessage, nil)
            callback(.failed(predictionError))
            return
        }
        offlineService.identify(request.image,
                                type: request.identifyType,
                                onEvent: callback)
    }

    // MARK: -
    func mergeResults(offlineResult: IdentifyResult?,
                      onlineResult: IdentifyResult?,
                      callback: @escaping  IdentifyEventHandler) {

        if offlineResult == nil && onlineResult == nil {
            let message = InterpretMultiServiceErrorMessage.interpretTextNoResult.errorDescription
            let recoveryMessage = InterpretMultiServiceErrorMessage.interpretTextNoResult.recoverySuggestion
            let predictionError = PredictionsError.service(message, recoveryMessage, nil)
            callback(.failed(predictionError))
        }

        guard let finalOfflineResult = offlineResult else {
            // We are sure that the value will be non-nil at this point.
            callback(.completed(onlineResult!))
            return
        }

        guard let finalOnlineResult = onlineResult else {
            callback(.completed(finalOfflineResult))
            return
        }

        if finalOnlineResult is IdentifyLabelsResult || finalOfflineResult is IdentifyLabelsResult {
            //merge labels result
            // swiftlint:force_cast disable
            guard let onlineLabelResult = finalOnlineResult as? IdentifyLabelsResult,
                let offlineLabelResult = finalOfflineResult as? IdentifyLabelsResult else {
                    //this should never happen, something went seriously wrong throw error
                    let message = IdentifyMultiServiceErrorMessage.noResultIdentifyService.errorDescription
                    let recoveryMessage = IdentifyMultiServiceErrorMessage.noResultIdentifyService.recoverySuggestion
                    let predictionError = PredictionsError.service(message, recoveryMessage, nil)
                    callback(.failed(predictionError))
                    return
            }
            let mergedResult = mergeLabelResult(onlineLabelResult: onlineLabelResult,
                                           offlineLabelResult: offlineLabelResult)
            callback(.completed(mergedResult))
            return
        } else if finalOnlineResult is IdentifyTextResult || finalOnlineResult is IdentifyTextResult {
           // swiftlint:force_cast disable
           guard let onlineTextResult = finalOnlineResult as? IdentifyTextResult,
               let offlineTextResult = finalOfflineResult as? IdentifyTextResult else {
                   //this should never happen, something went seriously wrong throw error
                   let message = IdentifyMultiServiceErrorMessage.noResultIdentifyService.errorDescription
                   let recoveryMessage = IdentifyMultiServiceErrorMessage.noResultIdentifyService.recoverySuggestion
                   let predictionError = PredictionsError.service(message, recoveryMessage, nil)
                   callback(.failed(predictionError))
                   return
           }
           let mergedResult = mergeTextResult(onlineTextResult: onlineTextResult,
                                          offlineTextResult: offlineTextResult)
           callback(.completed(mergedResult))
           return
        }
    }

    func mergeLabelResult(onlineLabelResult: IdentifyLabelsResult,
                          offlineLabelResult: IdentifyLabelsResult) -> IdentifyLabelsResult {
        var combinedLabels = Set<Label>()

        let onlineLabelSet = Set<Label>(onlineLabelResult.labels)
        let offlineLabelSet = Set<Label>(offlineLabelResult.labels)

        //first find the labels that are the same
        let intersectingLabels = onlineLabelSet.intersection(offlineLabelSet)
        //loop through to find higher confidences and retain those labels and add to final result
        for label in intersectingLabels {
            let onlineIndex = onlineLabelSet.firstIndex(of: label)!
            let offlineIndex = offlineLabelSet.firstIndex(of: label)!
            let onlineLabel = onlineLabelSet[onlineIndex]
            let offlineLabel = offlineLabelSet[offlineIndex]
            let labelWithHigherConfidence = onlineLabel.higherConfidence(compareTo: offlineLabel)
            combinedLabels.insert(labelWithHigherConfidence)
        }

        //get the differences
        //leaving here for performance comparison
        // let differingLabels = Array(onlineLabelSet.symmetricDifference(offlineLabelSet))
        // combinedLabels.append(contentsOf: differingLabels)
        combinedLabels = combinedLabels.union(onlineLabelSet)
        combinedLabels = combinedLabels.union(offlineLabelSet)

        return IdentifyLabelsResult(labels: Array(combinedLabels),
                                    unsafeContent: onlineLabelResult.unsafeContent ?? nil)

    }

    func mergeTextResult(onlineTextResult: IdentifyTextResult,
                         offlineTextResult: IdentifyTextResult) -> IdentifyTextResult {

        guard let onlineLines = onlineTextResult.identifiedLines else {
            return IdentifyTextResult(fullText: onlineTextResult.fullText,
                                      words: onlineTextResult.words,
                                      rawLineText: onlineTextResult.rawLineText,
                                      identifiedLines: offlineTextResult.identifiedLines)
        }

        guard let offlineLines = offlineTextResult.identifiedLines else {
            return onlineTextResult
        }

        let onlineLineSet = Set<IdentifiedLine>(onlineLines)
        let offlineLineSet = Set<IdentifiedLine>(offlineLines)
        //TODO: figure out how to compare bounding boxes to avoid removing duplicate text in diff places
        let mergedLines = Array(onlineLineSet.union(offlineLineSet))

        //offline result doesn't return anything except identified lines so
        //merging them plus the other stuff from online is a merged result
        return IdentifyTextResult(fullText: onlineTextResult.fullText,
                                  words: onlineTextResult.words,
                                  rawLineText: onlineTextResult.rawLineText,
                                  identifiedLines: mergedLines)
    }
}

extension Label: Hashable {

    public static func == (lhs: Label, rhs: Label) -> Bool {
        return lhs.name.lowercased() == rhs.name.lowercased()
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(name.lowercased())
    }

    func higherConfidence(compareTo: Label) -> Label {
        guard let firstMetadata = self.metadata,
            let secondMetadata = compareTo.metadata else {
                return self
        }
        return max(firstMetadata, secondMetadata) == firstMetadata ? self : compareTo
    }
}

extension LabelMetadata: Hashable, Comparable {

    public static func == (lhs: LabelMetadata, rhs: LabelMetadata) -> Bool {
        return lhs.confidence == rhs.confidence
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(confidence)
    }

    public static func < (lhs: LabelMetadata, rhs: LabelMetadata) -> Bool {
        return lhs.confidence < rhs.confidence
    }
}

extension IdentifiedLine: Hashable {

    public static func == (lhs: IdentifiedLine, rhs: IdentifiedLine) -> Bool {
        return lhs.text == rhs.text
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(text)
    }
}
