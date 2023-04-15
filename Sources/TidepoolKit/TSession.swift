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

    // The authentication token returned via authentication and for use with any future API network requests.
    public let authenticationToken: String

    // The user id associated with the authentication token required by some API network requests.
    public let userId: String

    // The username associated with this account, when the session was created
    public let username: String

    // The value of the optional X-Tidepool-Trace-Session header added to any future API network requests. The default UUID string
    // is usually sufficient, but can be changed or removed.
    public let trace: String?

    // The date the session was created
    public let createdDate: Date
    
    public init(environment: TEnvironment, authenticationToken: String, userId: String, username: String, trace: String? = UUID().uuidString, createdDate: Date = Date()) {
        self.environment = environment
        self.authenticationToken = authenticationToken
        self.userId = userId
        self.username = username
        self.trace = trace
        self.createdDate = createdDate
    }

    public var wantsRefresh: Bool { createdDate.addingTimeInterval(Self.refreshInterval) < Date() }

    public static let refreshInterval: TimeInterval = .minutes(5)
}

extension TSession {
    public init(session: TSession, authenticationToken: String) {
        self.init(environment: session.environment, authenticationToken: authenticationToken, userId: session.userId, username: session.username, trace: session.trace)
    }
}
