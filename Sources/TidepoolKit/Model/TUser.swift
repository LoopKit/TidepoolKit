//
//  TUser.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 4/15/23.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import Foundation

/* {
 "emailVerified":true,
 "emails":[
    "name@email.org"
 ],
 "roles":[
    "default-roles-integration",
    "patient"
 ],
 "termsAccepted":"2023-01-19T21:34:27+00:00",
 "userid":"e631fc5a-1234-4686-a498-8f2bbfec55b6",
 "username":"name@email.org"
} */


public struct TUser: Codable, Equatable {
    public var emailVerified: Bool
    public var emails: [String]
    public var roles: [String]
    public var termsAccepted: Date
    public var userid: String
    public var username: String
}
