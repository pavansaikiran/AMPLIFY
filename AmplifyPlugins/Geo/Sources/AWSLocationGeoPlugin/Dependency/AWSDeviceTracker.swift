//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Amplify
import Foundation
import CoreLocation
import AWSLocation

class AWSDeviceTracker: NSObject, CLLocationManagerDelegate, AWSDeviceTrackingBehavior {
    
    static let lastLocationUpdateTimeKey = "com.amazonaws.Amplify.AWSLocationGeoPlugin.lastLocationUpdateTime"
    static let lastUpdatedLocationKey = "com.amazonaws.Amplify.AWSLocationGeoPlugin.lastUpdatedLocation"
    static let deviceIDKey = "com.amazonaws.Amplify.AWSLocationGeoPlugin.deviceID"
    static let batchSizeForLocationInput = 10
    
    let locationManager: CLLocationManager
    let locationStore: LocationPersistenceBehavior
    let locationService: AWSLocationBehavior
    let networkMonitor: GeoNetworkMonitor
    var options: Geo.LocationManager.TrackingSessionOptions
    
    init(options: Geo.LocationManager.TrackingSessionOptions,
         locationManager: CLLocationManager,
         locationService: AWSLocationBehavior) throws {
        self.options = options
        self.locationManager = locationManager
        self.locationService = locationService
        do {
            self.locationStore = try SQLiteLocationPersistenceAdapter(fileSystemBehavior: LocationFileSystem())
        } catch {
            throw Geo.Error.unknown(GeoPluginErrorConstants.errorInitializingLocalStore.errorDescription,
                                    GeoPluginErrorConstants.errorInitializingLocalStore.recoverySuggestion,
                                    error)
        }
        self.networkMonitor = GeoNetworkMonitor()
    }
    
    func configure(with options: Geo.LocationManager.TrackingSessionOptions) {
        self.options = options
        locationManager.delegate = self
        configureLocationManager(with: options)
    }
    
    // setting `CLLocationManager` properties requires a UITest or running test in App mode
    // with appropriate location permissions. Moved out to separate method to facilitate
    // unit testing
    func configureLocationManager(with options: Geo.LocationManager.TrackingSessionOptions) {
        locationManager.desiredAccuracy = options.desiredAccuracy.clLocationAccuracy
        locationManager.allowsBackgroundLocationUpdates = options.allowsBackgroundLocationUpdates
        locationManager.pausesLocationUpdatesAutomatically = options.pausesLocationUpdatesAutomatically
        locationManager.activityType = options.activityType
        #if !os(macOS)
        locationManager.showsBackgroundLocationIndicator = options.showsBackgroundLocationIndicator
        #endif
        locationManager.distanceFilter = options.distanceFilter
    }
    
    func startTracking(for device: Geo.Device) throws {
        networkMonitor.start()
        UserDefaults.standard.removeObject(forKey: AWSDeviceTracker.deviceIDKey)
        UserDefaults.standard.set(device.id, forKey: AWSDeviceTracker.deviceIDKey)
        locationManager.delegate = self
        try checkPermissionsAndStartTracking()
    }
    
    func stopTracking() {
        // flush out stored events
        batchSendLocationsToService(positions: mapStoredLocationsToPositions())
        networkMonitor.cancel()
        locationManager.stopUpdatingLocation()
        locationManager.stopMonitoringSignificantLocationChanges()
        locationManager.delegate = nil
        UserDefaults.standard.removeObject(forKey: AWSDeviceTracker.deviceIDKey)
        UserDefaults.standard.removeObject(forKey: AWSDeviceTracker.lastLocationUpdateTimeKey)
        UserDefaults.standard.removeObject(forKey: AWSDeviceTracker.lastUpdatedLocationKey)
    }
    
    public func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        if let clError = error as? CLError {
                switch clError {
                case CLError.denied:
                    // user denied location services, stop tracking
                    stopTracking()
                default:
                    Amplify.log.error(error: error)
                }
            } else {
                Amplify.log.error(error: error)
            }
    }
    
    public func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        do {
            try checkPermissionsAndStartTracking()
        } catch {
            Amplify.log.error(error: error)
        }
    }
    
    public func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        // if network is unreachable and `disregardLocationUpdatesWhenOffline` is set,
        // don't store locations in local database
        if options.disregardLocationUpdatesWhenOffline && !networkMonitor.networkConnected() {
            return
        }
        
        let currentTime = Date()
        // check if trackUntil time has elapsed
        if(options.trackUntil < currentTime) {
            var allPositions = mapReceivedLocationsToPositions(receivedLocations: locations, currentTime: currentTime)
            allPositions.append(contentsOf: mapStoredLocationsToPositions())
            batchSendLocationsToService(positions: allPositions)
            stopTracking()
            return
        }
        
        // fetch last saved location and update time
        var lastUpdatedLocation : CLLocation?
        if let loadedLocation = UserDefaults.standard.data(forKey: AWSDeviceTracker.lastUpdatedLocationKey),
           let decodedLocation = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(loadedLocation) as? CLLocation {
            lastUpdatedLocation = decodedLocation
        }
        let lastLocationUpdateTime = UserDefaults.standard.object(forKey: AWSDeviceTracker.lastLocationUpdateTimeKey) as? Date
        
        let thresholdReached = options.batchingOption._thresholdReached(
            Geo.LocationManager.BatchingOption.LocationUpdate(timeStamp: lastLocationUpdateTime,
                                                              position: lastUpdatedLocation),
            Geo.LocationManager.BatchingOption.LocationUpdate(timeStamp: currentTime,
                                                              position: locations.last)
        )
        
        if thresholdReached && networkMonitor.networkConnected() {
            var allPositions = mapReceivedLocationsToPositions(receivedLocations: locations, currentTime: currentTime)
            allPositions.append(contentsOf: mapStoredLocationsToPositions())
            
            if let didUpdateLocations = options.locationProxyDelegate.didUpdateLocations {
                didUpdateLocations(allPositions)
            } else {
                batchSendLocationsToService(positions: allPositions)
            }
        } else {
            batchSaveLocationsToLocalStore(receivedLocations: locations, currentTime: currentTime)
        }
        
        // save lastLocation and last time a location update is received
        UserDefaults.standard.set(currentTime, forKey: AWSDeviceTracker.lastLocationUpdateTimeKey)
        if let lastReceivedLocation = locations.last,
            let encodedLocation = try? NSKeyedArchiver.archivedData(withRootObject: lastReceivedLocation, requiringSecureCoding: false) {
            UserDefaults.standard.set(encodedLocation, forKey: AWSDeviceTracker.lastUpdatedLocationKey)
        } else {
            Amplify.log.error("Error storing last received location in UserDefaults")
        }
    }
    
    func getLocationsFromLocalStore() throws -> [PositionInternal] {
        let storedLocations = try locationStore.getAll()
        try locationStore.removeAll()
        return storedLocations
    }
    
    func batchSaveLocationsToLocalStore(receivedLocations: [CLLocation], currentTime: Date) {
        do {
            guard let deviceID = UserDefaults.standard.object(forKey: AWSDeviceTracker.deviceIDKey) as? String else {
                Amplify.log.error("Not able to fetch deviceId from UserDefaults")
                let locations = receivedLocations.map({
                    Geo.Location(latitude: $0.coordinate.latitude, longitude: $0.coordinate.longitude) })
                sendHubErrorEvent(locations: receivedLocations)
                return
            }
            
            let positionsToStore = receivedLocations.map({ PositionInternal(timeStamp: currentTime,
                                                                            latitude: $0.coordinate.latitude,
                                                                            longitude: $0.coordinate.longitude,
                                                                            tracker: options.tracker!,
                                                                            deviceID: deviceID) })
            try self.locationStore.insert(positions: positionsToStore)
        } catch {
            let geoError = Geo.Error.unknown(
                GeoPluginErrorConstants.errorSavingLocationsToLocalStore.errorDescription, GeoPluginErrorConstants.errorSavingLocationsToLocalStore.recoverySuggestion,
                error)
            sendHubErrorEvent(error: geoError, locations: receivedLocations)
        }
    }

    func mapReceivedLocationsToPositions(receivedLocations: [CLLocation], currentTime: Date) -> [Position] {
        guard let deviceId = UserDefaults.standard.object(forKey: AWSDeviceTracker.deviceIDKey) as? String else {
            Amplify.log.error("Not able to fetch deviceId from UserDefaults")
            let error = Geo.Error.unknown(
                GeoPluginErrorConstants.errorSaveLocationsFailed.errorDescription, GeoPluginErrorConstants.errorSaveLocationsFailed.recoverySuggestion)
            sendHubErrorEvent(error: error, locations: receivedLocations)
            return []
        }
        
        return receivedLocations.map( {
            Position(timeStamp: currentTime,
                     latitude: $0.coordinate.latitude,
                     longitude: $0.coordinate.longitude,
                     tracker: options.tracker!,
                     deviceID: deviceId)
        })
    }
    
    private func mapStoredLocationsToPositions() -> [Position] {
        do {
            let storedLocations = try getLocationsFromLocalStore()
            return storedLocations.map( {
                Position(timeStamp: $0.timeStamp,
                         latitude: $0.latitude,
                         longitude: $0.longitude,
                         tracker: $0.tracker,
                         deviceID: $0.deviceID)
            } )
        } catch {
            Amplify.log.error("Unable to convert stored locations to positions.")
            let geoError = Geo.Error.unknown(
                GeoPluginErrorConstants.errorSaveLocationsFailed.errorDescription, GeoPluginErrorConstants.errorSaveLocationsFailed.recoverySuggestion,
                error)
            sendHubErrorEvent(error: geoError, locations: [Position]())
        }
        return []
    }
    
    func batchSendLocationsToService(positions: [Position]) {
        // send stored locations to service
        let positionChunks = positions.chunked(into: AWSDeviceTracker.batchSizeForLocationInput)
        for chunk in positionChunks {
            // start a new task for each chunk
            Task {
                do {
                    let locationUpdates = chunk.map ( {
                        LocationClientTypes.DevicePositionUpdate(
                            accuracy: nil,
                            deviceId: $0.deviceID,
                            position: [$0.longitude, $0.latitude],
                            positionProperties: nil,
                            sampleTime: Date())
                    } )
                    let input = BatchUpdateDevicePositionInput(trackerName: options.tracker!, updates: locationUpdates)
                    let response = try await locationService.updateLocation(forUpdateDevicePosition: input)
                     if let error = response.errors?.first as? Error {
                         Amplify.log.error("Unable to convert stored locations to positions.")
                         let geoError = Geo.Error.unknown(
                             GeoPluginErrorConstants.errorSaveLocationsFailed.errorDescription, GeoPluginErrorConstants.errorSaveLocationsFailed.recoverySuggestion,
                             error)
                         sendHubErrorEvent(error: geoError, locations: positions)
                        throw GeoErrorHelper.mapAWSLocationError(error)
                     }
                } catch {
                    Amplify.log.error("Unable to convert stored locations to positions.")
                    let geoError = Geo.Error.unknown(
                        GeoPluginErrorConstants.errorSaveLocationsFailed.errorDescription, GeoPluginErrorConstants.errorSaveLocationsFailed.recoverySuggestion,
                        error)
                    sendHubErrorEvent(error: geoError, locations: positions)
                }
            }
        }
    }
    
    func checkPermissionsAndStartTracking() throws {
        let authorizationStatus: CLAuthorizationStatus

        if #available(iOS 14, macOS 11.0, *) {
            authorizationStatus = locationManager.authorizationStatus
        } else {
            authorizationStatus = CLLocationManager.authorizationStatus()
        }
        switch authorizationStatus {
        case .authorized, .authorizedAlways, .authorizedWhenInUse:
            locationManager.startUpdatingLocation()
            if options.wakeAppForSignificantLocationChanges {
                locationManager.startMonitoringSignificantLocationChanges()
            }
        case .notDetermined:
            if options.requestAlwaysAuthorization {
                locationManager.requestAlwaysAuthorization()
            } else {
                locationManager.requestWhenInUseAuthorization()
            }
        case .restricted, .denied:
            stopTracking()
            throw Geo.Error.unknown(GeoPluginErrorConstants.missingPermissions.errorDescription,
                                    GeoPluginErrorConstants.missingPermissions.recoverySuggestion)
        @unknown default:
            throw Geo.Error.unknown(GeoPluginErrorConstants.missingPermissions.errorDescription,
                                    GeoPluginErrorConstants.missingPermissions.recoverySuggestion)
        }
    }
    
    func sendHubErrorEvent(error: Geo.Error? = nil, locations: [CLLocation]) {
        let geoLocations = locations.map({
            Geo.Location(latitude: $0.coordinate.latitude, longitude: $0.coordinate.longitude) })
        let data = AWSGeoHubPayloadData(error: error, locations: geoLocations)
        let payload = HubPayload(eventName: HubPayload.EventName.Geo.saveLocationFailed, data: data)
        Amplify.Hub.dispatch(to: .geo, payload: payload)
    }
    
    func sendHubErrorEvent(error: Geo.Error? = nil, locations: [Position]) {
        let geoLocations = locations.map({
            Geo.Location(latitude: $0.latitude, longitude: $0.longitude) })
        let data = AWSGeoHubPayloadData(error: error, locations: geoLocations)
        let payload = HubPayload(eventName: HubPayload.EventName.Geo.saveLocationFailed, data: data)
        Amplify.Hub.dispatch(to: .geo, payload: payload)
    }
}

extension Array {
    func chunked(into size: Int) -> [[Element]] {
        return stride(from: 0, to: count, by: size).map {
            Array(self[$0 ..< Swift.min($0 + size, count)])
        }
    }
}
