//
//  TCreator.swift
//  TidepoolKit
//
//  Created by Nathaniel Hamming on 2023-06-15.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import Foundation

public struct TCreator: Codable, Equatable {
    public var userid: String
    public var profile: TProfile?
    
    public init(userid: String, profile: TProfile?) {
        self.userid = userid
        self.profile = profile
    }
}
