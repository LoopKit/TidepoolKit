//
//  ProviderConfig.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 4/15/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import Foundation

struct ProviderConfiguration: Codable, Equatable {

    var issuer: String
    var authorizationEndpoint: String
    var tokenEndpoint: String
    var userinfoEndpoint: String?
    var endSessionEndpoint: String?
    var revocationEndpoint: String?
    var revocationEndpointAuthMethodsSupported: [String]?
    var grantTypesTupported: [String]?

}
