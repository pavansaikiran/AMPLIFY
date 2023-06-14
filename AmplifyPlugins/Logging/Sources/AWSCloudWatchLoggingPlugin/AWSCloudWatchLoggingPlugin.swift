//
// Copyright Amazon.com Inc. or its affiliates.
// All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

import AWSCloudWatchLogs
import AWSPluginsCore
import Amplify
import Combine
import Foundation

/// CloudWatchLoggingPlugin attempts to extract the proper CloudWatch
/// values from the application's Amplify configuration in order to
/// upload to a given log group. If no such configuration exists, this plugin
/// delegates all calls to the default Console logger implementation.
///
/// - Tag: CloudWatchLoggingPlugin
public class AWSCloudWatchLoggingPlugin: LoggingCategoryPlugin {    
    /// An instance of the authentication service.
    var loggingClient: AWSCloudWatchLoggingCategoryClient!
    var queue: DispatchQueue = .main
    
    var loggingPluginConfiguration: AWSCloudWatchLoggingPluginConfiguration?
    var remoteLoggingConstraintsProvider: RemoteLoggingConstraintsProvider?
    
    public var key: PluginKey {
        return PluginConstants.awsCloudWatchLoggingPluginKey
    }
    
    public var `default`: Logger {
        return LoggerProxy(targets: [
            loggingClient.default
        ])
    }
    
    public init(
        loggingPluginConfiguration: AWSCloudWatchLoggingPluginConfiguration? = nil,
        remoteLoggingConstraintsProvider: RemoteLoggingConstraintsProvider? = nil
    ) {
        self.loggingPluginConfiguration = loggingPluginConfiguration
        self.remoteLoggingConstraintsProvider = remoteLoggingConstraintsProvider
        if let configuration = self.loggingPluginConfiguration {
            let authService = AWSAuthService()
            
            self.loggingClient = AWSCloudWatchLoggingCategoryClient(
                enable: configuration.enablePlugin,
                credentialsProvider: authService.getCredentialsProvider(),
                authentication: Amplify.Auth,
                logGroupName: configuration.logGroupName,
                region: configuration.region
            )
        }
    }

    public func logger(forCategory category: String, logLevel: LogLevel) -> Logger {
        return LoggerProxy(targets: [loggingClient.logger(forCategory: category, logLevel: logLevel)])
    }

    public func logger(forCategory category: String) -> Logger {
        return LoggerProxy(targets: [loggingClient.logger(forCategory: category)])
    }
    
    public func logger(forNamespace namespace: String) -> Logger {
        return LoggerProxy(targets: [loggingClient.logger(forCategory: namespace)])
        
    }
    
    public func logger(forCategory category: String, forNamespace namespace: String) -> Logger {
        return LoggerProxy(targets: [loggingClient.logger(forCategory: category)])
    }
    
    /// enable plugin
    public func enable() {
        loggingClient.enable()
    }
    
    /// disable plugin
    public func disable() {
        loggingClient.disable()
    }
    
    /// send logs on-demand to AWS CloudWatch
    public func flushLogs() async throws {
        
    }
    
    /// Retrieve the escape hatch to perform low level operations on AWSCloudWatch
    ///
    /// - Returns: AWS CloudWatch Client
    public func getEscapeHatch() -> CloudWatchLogsClientProtocol? {
        let authService = AWSAuthService()
        guard let region = self.loggingPluginConfiguration?.region, let configuration = try? CloudWatchLogsClient.CloudWatchLogsClientConfiguration(
            credentialsProvider: authService.getCredentialsProvider(),
            region: region
        ) else {
            return nil
        }
        return CloudWatchLogsClient(config: configuration)
    }
    
    /// Resets the state of the plugin.
    ///
    /// Calls the reset methods on the storage service and authentication service to clean up resources. Setting the
    /// storage service, authentication service, and queue to nil to allow deallocation.
    public func reset() async {
        await loggingClient.reset()
    }
    
    /// Configures AWSS3StoragePlugin with the specified configuration.
    ///
    /// This method will be invoked as part of the Amplify configuration flow. Retrieves the bucket, region, and
    /// default configuration values to allow overrides on plugin API calls.
    ///
    /// - Parameter configuration: The configuration specified for this plugin
    /// - Throws:
    ///   - PluginError.pluginConfigurationError: If one of the configuration values is invalid or empty
    public func configure(using configuration: Any?) throws {
        if self.loggingPluginConfiguration == nil, let configuration = try? AWSCloudWatchLoggingPluginConfiguration(bundle: Bundle.main) {
            self.loggingPluginConfiguration = configuration
            let authService = AWSAuthService()
            self.loggingClient = AWSCloudWatchLoggingCategoryClient(
                enable: configuration.enablePlugin,
                credentialsProvider: authService.getCredentialsProvider(),
                authentication: Amplify.Auth,
                logGroupName: configuration.logGroupName,
                region: configuration.region
            )
        }
        
        // Please note that the call to takeUserIdentifierFromCurrentUser needs
        // to happen **after** all plugins have had their chance to be
        // configured, so this is invoked in a future run loop pass.
        queue.async { [weak self] in
            self?.loggingClient.takeUserIdentifierFromCurrentUser()
        }
    }
}

extension AWSCloudWatchLoggingPlugin: AmplifyVersionable { }
