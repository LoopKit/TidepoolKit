//
//  TEnvironment.swift
//  TidepoolKit
//
//  Created by Darin Krauss on 1/19/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import Foundation

/// Representation of a Tidepool API environment that includes a host and port. Typically discovered dynamically
/// via DNS SRV record lookup.
///
/// Network requests will use HTTPS only if port is 443. Otherwise, HTTP will be used.
public struct TEnvironment: Codable, Equatable {

    /// The host for the environment. For example, api.tidepool.org.
    public let host: String

    // The port for the environment. For example, 443.
    public let port: UInt16
    
    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var authenticationURL: URL {
        switch host {
        case "external.integration.tidepool.org":
            return URL(string: "https://auth.integration.tidepool.org/realms/integration/")!
        default:
            return URL(string: "https://auth.tidepool.org/realms/tidepool/")!
        }
    }

    public func url(path: String = "/", queryItems: [URLQueryItem]? = nil) throws -> URL {
        var components = URLComponents()
        components.host = host
        switch port {
            case 80:
                components.scheme = "http"
            case 443:
                components.scheme = "https"
            default:
                components.scheme = "http"
                components.port = Int(port)
        }
        components.path = path.hasPrefix("/") ? path : "/\(path)"
        components.queryItems = queryItems
        guard let url = components.url else {
            throw TError.invalidURL(components)
        }
        return url
    }

    static public var productionEnvironment: TEnvironment {
        return DNSSRVRecordsImplicit.first!.environment
    }

    /// Find environments  from the latest DNS SRV record lookup. Production is always the first element.
    static public func fetchEnvironments() async throws -> [TEnvironment] {
        return try await withCheckedThrowingContinuation { continuation in
            DNS.lookupSRVRecords(for: Self.DNSSRVRecordsDomainName) { result in
                switch result {
                case .failure(let error):
                    continuation.resume(throwing: TError.network(error))
                case .success(let records):
                    var records = records + Self.DNSSRVRecordsImplicit
                    records = records.map { record in
                        if record.host != "localhost" {
                            return record
                        }
                        return DNSSRVRecord(priority: UInt16.max, weight: record.weight, host: record.host, port: record.port)
                    }
                    let environments = records.sorted().environments
                    continuation.resume(returning: environments)
                }
            }
        }
    }

    private static let DNSSRVRecordsDomainName = "environments-srv.tidepool.org"
    private static let DNSSRVRecordsImplicit = [DNSSRVRecord(priority: UInt16.min, weight: UInt16.max, host: "app.tidepool.org", port: 443)]
}

extension TEnvironment: CustomStringConvertible {
    public var description: String { "\(host):\(port)" }
}
