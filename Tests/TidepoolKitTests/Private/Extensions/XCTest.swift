//
//  XCTest.swift
//  TidepoolKitTests
//
//  Created by Darin Krauss on 3/2/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import XCTest
import TidepoolKit

public func XCTAssertCodableAsJSON<T>(_ codable: @autoclosure () -> T, _ jsonObject: @autoclosure () -> Any, _ message: @autoclosure () -> String = "", file: StaticString = #file, line: UInt = #line) where T: Codable, T: Equatable {
    let codable = codable()
    let jsonObject = jsonObject()
    let message = message()

    // Compare semantically (parse JSON back to Foundation objects, compare via
    // NSDictionary/NSArray equality) rather than as raw strings. JSONEncoder and
    // JSONSerialization don't agree on every detail of textual output -- newer
    // Foundation emits Doubles at full IEEE-754 precision (e.g. 2.34 -> 2.3399...),
    // and key ordering can also differ -- but the parsed values are equivalent.
    func assertEncodableAsJSON() throws {
        let codableData = try JSONEncoder.tidepool.encode(codable)
        let codableParsed = try JSONSerialization.jsonObject(with: codableData)
        XCTAssertEqual(codableParsed as? NSObject, jsonObject as? NSObject, message, file: file, line: line)
    }

    func assertDecodableAsJSON() throws {
        let jsonData = try JSONSerialization.data(withJSONObject: jsonObject)
        let jsonCodable = try JSONDecoder.tidepool.decode(T.self, from: jsonData)
        XCTAssertEqual(jsonCodable, codable, message, file: file, line: line)
    }

    XCTAssertNoThrow(try assertEncodableAsJSON(), message, file: file, line: line)
    XCTAssertNoThrow(try assertDecodableAsJSON(), message, file: file, line: line)
}

public func XCTAssertCodableAsJSON<T>(_ codable: @autoclosure () -> T, _ jsonString: @autoclosure () -> String, _ message: @autoclosure () -> String = "", file: StaticString = #file, line: UInt = #line) where T: Codable, T: Equatable {
    let codable = codable()
    let jsonString = jsonString()
    let message = message()

    func assertEncodableAsJSON() throws {
        let codableData = try JSONEncoder.tidepool.encode(codable)
        let codableString = String(data: codableData, encoding: .utf8)
        XCTAssertNotNil(codableString, message, file: file, line: line)
        if let codableString = codableString {
            XCTAssertEqual(codableString, jsonString, message, file: file, line: line)
        }
    }

    func assertDecodableAsJSON() throws {
        let jsonData = jsonString.data(using: .utf8)
        XCTAssertNotNil(jsonData, message, file: file, line: line)
        if let jsonData = jsonData {
            let jsonCodable = try JSONDecoder.tidepool.decode(T.self, from: jsonData)
            XCTAssertEqual(jsonCodable, codable, message, file: file, line: line)
        }
    }

    XCTAssertNoThrow(try assertEncodableAsJSON(), message, file: file, line: line)
    XCTAssertNoThrow(try assertDecodableAsJSON(), message, file: file, line: line)
}

public class XCTestExpectationWithResult<Success, Failure>: XCTestExpectation where Failure: Error {
    var result: Result<Success, Failure>?

    func fulfill(_ result: Result<Success, Failure>) {
        self.result = result
        super.fulfill()
    }
}

public class XCTestExpectationWithError: XCTestExpectation {
    var error: TError?

    func fulfill(_ error: TError?) {
        self.error = error
        super.fulfill()
    }
}
