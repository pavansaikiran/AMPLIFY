//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import SQLite

/// This is a temporary placeholder class to interface with the SQLiteLocalStorageAdapter
/// This class needs to be updated to support Codable queries that can decode into a PinpointEvent object
class AnalyticsEventStorage {
    private let dbAdapter: LocalStorageProtocol
    
    /// Initializer
    /// - Parameter dbAdapter: a LocalStorageProtocol adapter
    init(dbAdapter: LocalStorageProtocol) {
        self.dbAdapter = dbAdapter
    }
    
    /// Insert an Event into the Even table
    /// - Parameter bindings: a collection of values to insert into the Event
    func insertEvent(bindings: [Binding]) throws {
        let insertStatement = """
            INSERT INTO Event (
            id, attributes, eventType, metrics,
            eventTimestamp, sessionId, sessionStartTime,
            sessionStopTime, timestamp, dirty, retryCount)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        _ = try dbAdapter.executeSqlQuery(insertStatement, bindings)
    }
    
    /// Delete events from the Events older than a specified timestamp
    /// - Parameter timeStamp: The timestamp to query against
    func deleteEventsOlderThan(timeStamp: Binding) throws {
        let deleteStatement = """
         DELETE FROM Event
         WHERE timestamp < ?"
        """
        _ = try dbAdapter.executeSqlQuery(deleteStatement, [timeStamp])
    }
    
    /// Delete all dirty events from the Event and DirtyEvent tables
    func deleteDirtyEvents() throws {
        let deleteFromDirtyEventTable = "DELETE FROM DirtyEvent"
        let deleteFromEventTable = "DELETE FROM Event WHERE dirty = true"
        _ = try dbAdapter.executeSqlQuery(deleteFromDirtyEventTable, [])
        _ = try dbAdapter.executeSqlQuery(deleteFromEventTable, [])
    }
    
    /// Delete the oldest event from the Event table
    func deleteOldestEvent() throws {
        let deleteStatements = """
        DELETE FROM Event
        WHERE id IN (
        SELECT id
        FROM Event
        ORDER BY timestamp ASC
        LIMIT 1)
        """
        _ = try dbAdapter.executeSqlQuery(deleteStatements, [])
    }
    
    /// Delete all events from the Event table
    func deleteAllEvents() throws {
        let deleteStatement = "DELETE FROM Event"
        _ = try dbAdapter.executeSqlQuery(deleteStatement, [])
    }
    
    /// Get the oldest event with limit
    /// - Parameter limit: The number of query result to limit
    func getEventsWith(limit: Binding) throws {
        let queryStatement = """
        SELECT id, attributes, eventType, metrics, eventTimestamp, sessionId, sessionStartTime, sessionStopTime, timestamp, retryCount
        FROM Event
        ORDER BY timestamp ASC
        LIMIT ?
        """
        _ = try dbAdapter.executeSqlQuery(queryStatement, [limit])
    }
    
    /// Get the oldest dirty events with limit
    /// - Parameter limit: The number of query result to limit
    func getDirtyEventsWith(limit: Binding) throws {
        let queryStatement = """
        SELECT id, attributes, eventType, metrics, eventTimestamp, sessionId, sessionStartTime, sessionStopTime, timestamp, retryCount
        FROM DirtyEvent
        ORDER BY timestamp ASC
        LIMIT ?
        """
        _ = try dbAdapter.executeSqlQuery(queryStatement, [limit])
    }
    
}
