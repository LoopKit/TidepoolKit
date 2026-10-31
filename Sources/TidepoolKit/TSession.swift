//
//  TSession.swift
//  TidepoolKit
//
//  Created by Darin Krauss on 2/17/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import Foundation

/// Representation of a Tidepool API session, including the environment, an authentication token, and a user id.
public struct TSession: Codable, Equatable {

    // The environment used for authentication and for any future API network requests.
    public let environment: TEnvironment

    // The access token returned via authentication and for use with any future API network requests.
    public let accessToken: String

    // Expiration date for the access token.
    public let accessTokenExpiration: Date?

    // The refresh token returned via authentication, used to refresh the access token.
    public let refreshToken: String?

    // The user id associated with the authentication token required by some API network requests.
    public let userId: String

    // The username associated with this account, when the session was created
    public let username: String
    
    // The roles associated with this account, when the session was created
    public let userRoles: [String]

    // The value of the optional X-Tidepool-Trace-Session header added to any future API network requests. The default UUID string
    // is usually sufficient, but can be changed or removed.
    public let trace: String?

    // The date the session was created
    public let createdDate: Date
    
    public init(environment: TEnvironment, accessToken: String, accessTokenExpiration: Date?, refreshToken: String?, userId: String, username: String, userRoles: [String], trace: String? = UUID().uuidString, createdDate: Date = Date()) {
        self.environment = environment
        self.accessToken = accessToken
        self.accessTokenExpiration = accessTokenExpiration
        self.refreshToken = refreshToken
        self.userId = userId
        self.username = username
        self.userRoles = userRoles
        self.trace = trace
        self.createdDate = createdDate
    }

    public func shouldRefresh(after date: Date = Date()) -> Bool {
        guard let accessTokenExpiration else {
            return false
        }
        return date.timeIntervalSince(accessTokenExpiration) > 0
    }

    private enum CodingKeys: String, CodingKey {
        case environment
        case accessToken
        case accessTokenExpiration
        case refreshToken
        case userId
        case username
        case userRoles
        case trace
        case createdDate
    }

    // Custom decoder for backward compatibility with sessions persisted before
    // `userRoles` was added: old JSON lacks the key, so default to an empty array
    // rather than failing the whole decode (which would drop the saved session
    // on first launch after an upgrade and force the user to re-authenticate).
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.environment = try container.decode(TEnvironment.self, forKey: .environment)
        self.accessToken = try container.decode(String.self, forKey: .accessToken)
        self.accessTokenExpiration = try container.decodeIfPresent(Date.self, forKey: .accessTokenExpiration)
        self.refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        self.userId = try container.decode(String.self, forKey: .userId)
        self.username = try container.decode(String.self, forKey: .username)
        self.userRoles = try container.decodeIfPresent([String].self, forKey: .userRoles) ?? []
        self.trace = try container.decodeIfPresent(String.self, forKey: .trace)
        self.createdDate = try container.decode(Date.self, forKey: .createdDate)
    }
}
