//
//  TInfo.swift
//  TidepoolKit
//
//  Created by Rick Pasetto on 9/7/21.
//  Copyright © 2021 Tidepool Project. All rights reserved.
//

import Foundation

public struct TInfo: Codable, Equatable {
    public var versions: Versions?
    public var auth: Auth?

    public struct Auth: Codable, Equatable {
        public var realm: String?
        public var url: String?

        public var issuerURL: URL? {
            guard let realm, let url, let baseURL = URL(string: url) else {
                return nil
            }
            return baseURL.appendingPathComponent("realms/" + realm)
        }
    }

    public struct Versions: Codable, Equatable {
        public var loop: Loop?

        public struct Loop: Codable, Equatable {
            public var minimumSupported: String?
            public var criticalUpdateNeeded: [String]?
        }
    }
}
