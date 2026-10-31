//
//  TDeviceLogsMetadata.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 6/3/24.
//  Copyright © 2019 Tidepool Project. All rights reserved.
//

import Foundation

import Foundation

public struct TDeviceLogsMetadata: Codable, Equatable {
    public var id: String
    public var userId: String
    public var digestMD5: String
    public var mediaType: String
    public var size: Int
    public var createdTime: Date
    public var startAtTime: Date
    public var endAtTime: Date
}
