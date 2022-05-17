//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import Foundation
import SQLite

/// Local storage adapter that implements local storage using SQLite.swift
final class SQLiteLocalStorageAdapter: LocalStorageProtocol {
    private var connection: Connection?
    private var dbFilePath: URL?
    
    /// Initializer
    /// - Parameter databaseName: The database name
    convenience init(databaseName: String) throws {
        var dbFilePath = SQLiteLocalStorageAdapter.getDbFilePath(databaseName: databaseName)
        let connection: Connection
        do {
            connection = try Connection(dbFilePath.absoluteString)
            var urlResourceValues = URLResourceValues()
            urlResourceValues.isExcludedFromBackup = true
            try dbFilePath.setResourceValues(urlResourceValues)
        } catch {
            throw LocalStorageError.invalidDatabase(path: dbFilePath.absoluteString, error)
        }

        try self.init(connection: connection, dbFilePath: dbFilePath)
    }
    
    /// Initializer
    /// - Parameters:
    ///   - connection: SQLite Connection
    ///   - dbFilePath: Path to the database
    private init(
        connection: Connection,
        dbFilePath: URL? = nil
    ) throws {
        self.connection = connection
        self.dbFilePath = dbFilePath
        try initializeDatabase(connection: connection)
    }
    
    /// Create the Event and Dirty Event Tables
    private func createTables() throws {
        guard let connection = connection else {
            throw LocalStorageError.invalidOperation(causedBy: nil)
        }

        let createEventTableStatement = """
            CREATE TABLE IF NOT EXISTS Event (
            id TEXT NOT NULL,
            attributes BLOB NOT NULL,
            eventType TEXT NOT NULL,
            metrics BLOB NOT NULL,
            eventTimestamp TEXT NOT NULL,
            sessionId TEXT NOT NULL,
            sessionStartTime TEXT NOT NULL,
            sessionStopTime TEXT NOT NULL,
            timestamp REAL NOT NULL,
            dirty INTEGER NOT NULL,
            retryCount INTEGER NOT NULL)
        """
        let createDirtyEventTableStatement = """
            CREATE TABLE IF NOT EXISTS DirtyEvent (
            id TEXT NOT NULL,
            attributes BLOB NOT NULL,
            eventType TEXT NOT NULL,
            metrics BLOB NOT NULL,
            eventTimestamp TEXT NOT NULL,
            sessionId TEXT NOT NULL,
            sessionStartTime TEXT NOT NULL,
            sessionStopTime TEXT NOT NULL,
            timestamp REAL NOT NULL,
            dirty INTEGER NOT NULL,
            retryCount INTEGER NOT NULL)
        """

        do {
            try connection.execute(createEventTableStatement)
            try connection.execute(createDirtyEventTableStatement)
        } catch {
            throw LocalStorageError.invalidOperation(causedBy: error)
        }
    }
    
    /// Initilizes the database and create the table if it doesn't already exists
    /// - Parameter connection: SQLite connection
    private func initializeDatabase(connection: Connection) throws {
        let databaseInitializationStatement = """
        pragma auto_vacuum = full;
        pragma encoding = "utf-8";
        pragma foreign_keys = on;
        pragma case_sensitive_like = off;
        """

        try connection.execute(databaseInitializationStatement)
        try createTables()
    }
    
    /// Get the database file path constructed by the database name and the Documents directory
    /// - Parameter databaseName: The database file name
    /// - Returns: URL containing the location of the database
    internal static func getDbFilePath(databaseName: String) -> URL {
        guard let documentsPath = getDocumentPath() else {
            preconditionFailure("Could not create the database. The `.documentDirectory` is invalid")
        }
        return documentsPath.appendingPathComponent("\(databaseName).db")
    }
    
    /// Get document path
    /// - Returns: Optional URL to the Document path
    private static func getDocumentPath() -> URL? {
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    }
    
    /// Executes a SQL query
    /// - Parameters:
    ///   - statement: SQL query statement
    ///   - bindings: A collection of SQL bindings to prepare with the query statement
    /// - Returns: A SQL statement result from the query
    func executeSqlQuery(_ statement: String, _ bindings: [Binding?]) throws -> Statement {
        guard let connection = connection else {
            throw LocalStorageError.nilSQLiteConnection
        }
        
        do {
            let statement = try connection.prepare(statement).run(bindings)
            return statement
        } catch {
            throw LocalStorageError.invalidOperation(causedBy: error)
        }
    }
}
