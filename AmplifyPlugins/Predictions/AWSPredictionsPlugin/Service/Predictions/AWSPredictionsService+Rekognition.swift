//
// Copyright 2018-2019 Amazon.com,
// Inc. or its affiliates. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import Amplify
import AWSRekognition

extension AWSPredictionsService {
    func detectLabels(image: URL,
                      onEvent: @escaping AWSPredictionsService.RekognitionServiceEventHandler) {

        let request: AWSRekognitionDetectLabelsRequest = AWSRekognitionDetectLabelsRequest()
        let rekognitionImage: AWSRekognitionImage = AWSRekognitionImage()

        guard let imageData = try? Data(contentsOf: image) else {
           
            onEvent(.failed(
            .networkError("Something was wrong with the image file, make sure it exists.",
                          "Try choosing an image and sending it again.")))
            return
        }

        rekognitionImage.bytes = imageData
        request.image = rekognitionImage

        awsRekognition.detectLabels(request: request).continueWith { (task) -> Any? in
            guard task.error == nil else {
                let error = task.error! as NSError
                let predictionsErrorString = PredictionsErrorHelper.mapRekognitionError(error)
                onEvent(.failed(
                    .networkError(predictionsErrorString.errorDescription,
                                  predictionsErrorString.recoverySuggestion)))
                return nil
            }

            guard let result = task.result else {
                onEvent(.failed(
                    .unknownError("No result was found. An unknown error occurred",
                                  "Please try again.")))
                return nil
            }

            guard let labels = result.labels else {
                onEvent(.failed(
                    .networkError("No result was found.",
                                  "Please make sure the image integrity is maintained before sending")))
                return nil
            }

            let newLabels = IdentifyResultsUtils.processLabels(labels)
            onEvent(.completed(IdentifyLabelsResult(labels: newLabels)))
            return nil
        }
    }

    func detectCelebs(image: URL, onEvent: @escaping AWSPredictionsService.RekognitionServiceEventHandler) {
        let request: AWSRekognitionRecognizeCelebritiesRequest = AWSRekognitionRecognizeCelebritiesRequest()
        let rekognitionImage: AWSRekognitionImage = AWSRekognitionImage()

        let imageArray = image.absoluteString.components(separatedBy: "/")
        let imageKey = imageArray.last!
        guard let fileURL = FileManager().urls(for: .documentDirectory, in: .userDomainMask).first?.appendingPathComponent(imageKey),
            // get the data from the resulting url
            let imageData = try? Data(contentsOf: fileURL),
            // initialise your image object with the image data
            let uiimage = UIImage(data: imageData) else {
            onEvent(.failed(
            .networkError("Something was wrong with the image file, make sure it exists.",
                          "Try choosing an image and sending it again.")))
            return
        }

        rekognitionImage.bytes = uiimage.jpegData(compressionQuality: 0.2)!
        request.image = rekognitionImage

        awsRekognition.detectCelebs(request: request).continueWith { (task) -> Any? in
            guard task.error == nil else {
                let error = task.error! as NSError
                let predictionsErrorString = PredictionsErrorHelper.mapRekognitionError(error)
                onEvent(.failed(
                    .networkError(predictionsErrorString.errorDescription,
                                  predictionsErrorString.recoverySuggestion)))
                return nil
            }

            guard let result = task.result else {
                onEvent(.failed(
                    .unknownError("No result was found. An unknown error occurred",
                                  "Please try again.")))
                return nil
            }

            guard let celebs = result.celebrityFaces else {
                onEvent(.failed(
                    .networkError("No result was found.",
                                  "Please make sure the image integrity is maintained before sending")))
                return nil
            }

            let newCelebs = IdentifyResultsUtils.processCelebs(celebs)
            onEvent(.completed(IdentifyCelebsResult(celebrities: newCelebs)))
            return nil
        }

    }
}
