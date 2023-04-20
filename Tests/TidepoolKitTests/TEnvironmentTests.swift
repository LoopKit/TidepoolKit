//
//  TEnvironmentTests.swift
//  TidepoolKitTests
//
//  Created by Darin Krauss on 3/3/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import XCTest
import TidepoolKit

class TEnvironmentTests: XCTestCase {
    static let environment = TEnvironment(host: "test.tidepool.org", port: 443)
    static let environmentJSONDictionary: [String: Any] = [
        "host": "test.tidepool.org",
        "port": 443
    ]

    func testInitializer() {
        let environment = TEnvironmentTests.environment
        XCTAssertEqual(environment.host, "test.tidepool.org")
        XCTAssertEqual(environment.port, 443)
    }

    func testURLWithPort80() throws {
        let url = try TEnvironment(host: "test.tidepool.org", port: 80).url()
        XCTAssertEqual(url.absoluteString, "http://test.tidepool.org/")
    }

    func testURLWithPort443() throws {
        let url = try TEnvironment(host: "test.tidepool.org", port: 443).url()
        XCTAssertEqual(url.absoluteString, "https://test.tidepool.org/")
    }

    func testURLWithPortOther() throws {
        let url = try TEnvironment(host: "test.tidepool.org", port: 3000).url()
        XCTAssertEqual(url.absoluteString, "http://test.tidepool.org:3000/")
    }

    func testURLWithPathWithoutPrefix() throws {
        let url = try TEnvironmentTests.environment.url(path: "alpha/beta")
        XCTAssertEqual(url.absoluteString, "https://test.tidepool.org/alpha/beta")
    }

    func testURLWithPathWithPrefix() throws {
        let url = try TEnvironmentTests.environment.url(path: "/alpha/beta")
        XCTAssertEqual(url.absoluteString, "https://test.tidepool.org/alpha/beta")
    }

    func testURLWithQueryItems() throws {
        let queryItems = [URLQueryItem(name: "foo", value: "one"), URLQueryItem(name: "bar", value: "two")]
        let url = try TEnvironmentTests.environment.url(path: "/alpha/beta", queryItems: queryItems)
        XCTAssertEqual(url.absoluteString, "https://test.tidepool.org/alpha/beta?foo=one&bar=two")
    }

    func testImplicitEnvironments() {
        XCTAssertEqual(TEnvironment.productionEnvironment, TEnvironment(host: "app.tidepool.org", port: 443))
    }

    func testDescription() {
        XCTAssertEqual(TEnvironmentTests.environment.description, "test.tidepool.org:443")
    }

    func testCodableAsJSON() {
        XCTAssertCodableAsJSON(TEnvironmentTests.environment, TEnvironmentTests.environmentJSONDictionary)
    }
}
