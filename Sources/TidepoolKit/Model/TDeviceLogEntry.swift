//
//  TDeviceLogEntry.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 6/3/24.
//  Copyright © 2019 Tidepool Project. All rights reserved.
//


import Foundation

public struct TDeviceLogEntry: Codable, Equatable {
    public enum TDeviceLogEntryType: String, Codable {
        case send
        case receive
        case error
        case delegate
        case delegateResponse
        case connection
    }

    public var type: TDeviceLogEntryType
    public var managerIdentifier: String
    public var deviceIdentifier: String
    public var timestamp: Date
    public var message: String

    public init(type: TDeviceLogEntryType, managerIdentifier: String, deviceIdentifier: String, timestamp: Date, message: String) {
        self.type = type
        self.managerIdentifier = managerIdentifier
        self.deviceIdentifier = deviceIdentifier
        self.timestamp = timestamp
        self.message = message
    }
}
