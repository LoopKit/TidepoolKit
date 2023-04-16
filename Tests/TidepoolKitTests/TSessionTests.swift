//
//  TSessionTests.swift
//  TidepoolKitTests
//
//  Created by Darin Krauss on 3/3/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import XCTest
import TidepoolKit

class TSessionTests: XCTestCase {
    static let session = TSession(environment: TEnvironmentTests.environment,
                                  accessToken: "test-access-token",
                                  accessTokenExpiration: Date.test.addingTimeInterval(7 * 60 * 60),
                                  refreshToken: "test-refresh-token",
                                  userId: "1234567890",
                                  username: "test@test.com",
                                  trace: "test-trace",
                                  createdDate: Date.test)
    static let sessionJSONDictionary: [String: Any] = [
        "environment": TEnvironmentTests.environmentJSONDictionary,
        "accessToken": "test-access-token",
        "accessTokenExpiration": "2001-01-02T17:17:36.789Z",
        "userId": "1234567890",
        "username": "test@test.com",
        "refreshToken": "test-refresh-token",
        "trace": "test-trace",
        "createdDate": Date.testJSONString
    ]

    func testInitializer() {
        let session = TSessionTests.session
        XCTAssertEqual(session.environment, TEnvironmentTests.environment)
        XCTAssertEqual(session.accessToken, "test-access-token")
        XCTAssertEqual(session.userId, "1234567890")
        XCTAssertEqual(session.trace, "test-trace")
        XCTAssertEqual(session.createdDate, Date.test)
    }

    func testCodableAsJSON() {
        XCTAssertCodableAsJSON(TSessionTests.session, TSessionTests.sessionJSONDictionary)
    }
}
