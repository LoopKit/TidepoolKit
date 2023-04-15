//
//  TAPI.swift
//  TidepoolKit
//
//  Created by Darin Krauss on 1/20/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import Foundation
import AppAuth

/// Observer of the Tidepool API
public protocol TAPIObserver: AnyObject {

    /// Informs the observer that the API updated the session.
    ///
    /// - Parameters:
    ///     - session: The session.
    func apiDidUpdateSession(_ session: TSession?)
}

/// The Tidepool API
public actor TAPI {

    /// All currently known environments. Will always include, as the first element, production. It will additionally include any
    /// environments discovered from the latest DNS SRV record lookup. When an instance of TAPI is created it will automatically
    /// perform a DNS SRV record lookup in the background. A client should generally only have one instance of TAPI.
    public var environments: [TEnvironment]
    
    /// The default environment is derived from the host app group. See UserDefaults extension.
    nonisolated public var defaultEnvironment: TEnvironment? {
        get {
            UserDefaults.appGroup?.defaultEnvironment
        }
        set {
            UserDefaults.appGroup?.defaultEnvironment = newValue
        }
    }

    /// The URLSessionConfiguration used for all requests. The default is typically acceptable for most purposes. Any changes
    /// will only apply to subsequent requests.
    public var urlSessionConfiguration: URLSessionConfiguration {
        get {
            return urlSessionConfigurationLocked.value
        }
        set {
            urlSessionConfigurationLocked.mutate { $0 = newValue }
            urlSessionLocked.mutate { $0 = nil }
        }
    }

    /// The session used for all requests.
    public var session: TSession? {
        get {
            return sessionLocked.value
        }
        set {
            sessionLocked.mutate { $0 = newValue }
            observers.forEach { $0.apiDidUpdateSession(newValue) }
        }
    }

    public func setLogging(_ newLogging: TLogging) {
        logging = newLogging
    }

    private weak var logging: TLogging?

    private var observers = WeakSynchronizedSet<TAPIObserver>()

    private var clientId: String

    private var redirectURL: URL

    private var currentAuthorizationFlow: OIDExternalUserAgentSession?

    /// Create a new instance of TAPI. Automatically lookup additional environments in the background.
    ///
    /// - Parameters:
    ///   - clientId: The client id to use when authenticating
    ///   - redirectURL: The redirect url use when authenticating
    ///   - session: The initial session to use, if any.
    ///   - automaticallyFetchEnvironments: Automatically fetch an updated list of environments when created.
    public init(clientId: String, redirectURL: URL, session: TSession? = nil, automaticallyFetchEnvironments: Bool = true) {
        self.clientId = clientId
        self.redirectURL = redirectURL
        self.environments = TAPI.implicitEnvironments
        self.urlSessionConfigurationLocked = Locked(TAPI.defaultURLSessionConfiguration)
        self.urlSessionLocked = Locked(nil)
        self.sessionLocked = Locked(session)
        if automaticallyFetchEnvironments {
            Task {
                await fetchEnvironments()
            }
        }
    }

    /// Start observing the API.
    ///
    /// - Parameters:
    ///     - observer: The observer observing the API.
    ///     - queue: The Dispatch queue upon which to notify the observer of API changes.
    public func addObserver(_ observer: TAPIObserver, queue: DispatchQueue = .main) {
        observers.insert(observer, queue: queue)
    }

    /// Stop observing the API.
    ///
    /// - Parameters:
    ///     - observer: The observer observing the API.
    public func removeObserver(_ observer: TAPIObserver) {
        observers.removeElement(observer)
    }


    // MARK: - Environment

    /// Manually fetch the latest environments. Production is always the first element.
    ///
    /// - Parameters:
    ///   - completion: The completion function to invoke with the latest environments or any error.
    public func fetchEnvironments(completion: ((Result<[TEnvironment], TError>) -> Void)? = nil) {
        DNS.lookupSRVRecords(for: TAPI.DNSSRVRecordsDomainName) { result in
            switch result {
            case .failure(let error):
                self.logging?.error("Failure during DNS SRV record lookup [\(error)]")
                completion?(.failure(.network(error)))
            case .success(let records):
                var records = records + TAPI.DNSSRVRecordsImplicit
                records = records.map { record in
                    if record.host != "localhost" {
                        return record
                    }
                    return DNSSRVRecord(priority: UInt16.max, weight: record.weight, host: record.host, port: record.port)
                }
                let environments = records.sorted().environments
                self.environments = environments
                self.logging?.debug("Successful DNS SRV record lookup")
                completion?(.success(environments))
            }
        }
    }

    private func lookupOIDConfiguration(issuer: URL) async throws -> OIDServiceConfiguration {
        // Lookup OpenID Service configuration for this environment, for various OpenID endpoints
        let config: OIDServiceConfiguration = try await withCheckedThrowingContinuation { continuation in
            OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in
                guard error == nil else {
                    continuation.resume(throwing: TError.network(error))
                    return
                }

                guard let config = configuration else {
                    continuation.resume(throwing: TError.missingAuthenticationConfiguration)
                    return
                }

                continuation.resume(returning: config)
            }
        }
        return config
    }

    private func presentAuth(request: OIDAuthorizationRequest, presenting: UIViewController) async throws -> (String, OIDExternalUserAgentSession) {
        // Present the authentication session using AppAuth
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.main.async {
                var f: OIDExternalUserAgentSession? = nil
                f = OIDAuthState.authState(byPresenting: request, presenting: presenting) { authState, error in
                    if let error = error {
                        continuation.resume(throwing: TError.network(error))
                        return
                    }

                    guard let authState else {
                        continuation.resume(throwing: TError.missingAuthenticationState)
                        return
                    }

                    guard let accessToken = authState.lastTokenResponse?.accessToken else {
                        continuation.resume(throwing: TError.missingAuthenticationToken)
                        return
                    }

                    continuation.resume(returning: (accessToken, f!))
                }
            }
        }
    }

    // MARK: - Authentication

    /// Login to the Tidepool environment using AppAuth (OAuth2/OpenID-Connect)
    /// used internally by the LoginSignupViewController.
    ///
    /// - Parameters:
    ///   - environment: The environment to login.
    ///   - presenting: A UIViewController to present the login modal from. Can be UIApplication.shared.windows.first!.rootViewController!
    ///   - completion: The completion function to invoke with any error.
    public func login(environment: TEnvironment, presenting: UIViewController) async throws {

        // Lookup /info for current Tidepool environment, for issuer URL
        let info = try await getInfo(environment: environment)

        guard let issuer = info.auth?.issuerURL else {
            throw TError.missingAuthenticationIssuer
        }

        let config = try await lookupOIDConfiguration(issuer: issuer)

        let request = OIDAuthorizationRequest(
            configuration: config,
            clientId: self.clientId,
            clientSecret: nil,
            scopes: ["openid", "offline_access"],
            redirectURL: self.redirectURL,
            responseType: OIDResponseTypeCode,
            additionalParameters: [:]
        )

        let (accessToken, flow) = try await presentAuth(request: request, presenting: presenting)
        self.currentAuthorizationFlow = flow

        self.logging?.debug("Authorization successful, access token: \(accessToken)")

        // getAuthUser
        var userRequest = try createRequest(environment: environment, method: "GET", path: "/auth/user")
        userRequest.setValue(accessToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)

        let currentUser: TUser = try await performRequest(userRequest, allowSessionRefresh: true)

        self.session = TSession(environment: environment, authenticationToken: accessToken, userId: currentUser.userid, username: currentUser.username)
    }

    private func basicAuthorizationFromCredentials(email: String, password: String) -> String {
        let encodedCredentials = Data("\(email):\(password)".utf8).base64EncodedString()
        return "Basic \(encodedCredentials)"
    }

    /// Refresh the Tidepool API session.
    ///
    /// An .requestNotAuthenticated error indicates that the old session is no longer valid. All other errors
    /// indicate that the old session is still valid and refresh can be retried.
    ///

    public func refreshSession() async throws {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "GET", path: "/auth/login")
        do {
            let (response, data) = try await performRequest(request, allowSessionRefresh: false)
            if let authenticationToken = response.value(forHTTPHeaderField: "X-Tidepool-Session-Token"), !authenticationToken.isEmpty {
                self.session = TSession(session: session, authenticationToken: authenticationToken)
                return
            } else {
                throw TError.responseNotAuthenticated(response, data)
            }
        } catch {
            if case TError.requestNotAuthenticated = error {
                self.logging?.error("Authentication failed during session refresh request \(String(describing: request)), \(error)")
                self.session = nil
            }
            throw error
        }
    }

    /// Logout the Tidepool API session.
    ///
    public func logout() {
        self.session = nil
    }

    // MARK: - Info

    /// Get Tidepool environment information for the specified environment.
    ///
    /// - Parameters:
    ///   - environment: The environment to get the info for.
    /// - Returns: A ``TInfo`` structure
    public func getInfo(environment: TEnvironment) async throws -> TInfo {
        let request = try createRequest(environment: environment, method: "GET", path: "/info")
        return try await performRequest(request, allowSessionRefresh: false)
    }

    // MARK: - Profile

    /// Get the profile for the specified user id. If no user id is specified, then the session user id is used.
    ///
    /// - Parameters:
    ///   - userId: The user id for which to get the profile. If no user id is specified, then the session user id is used.
    ///   - completion: The completion function to invoke with any error.
    public func getProfile(userId: String? = nil) async throws -> TProfile {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "GET", path: "/metadata/\(userId ?? session.userId)/profile")
        return try await performRequest(request)
    }

    // MARK: - Prescriptions

    /// Claim the prescription for the session user id.
    ///
    /// - Parameters:
    ///   - prescriptionClaim: The prescription claim to submit.
    ///   - userId: The user id for which to claim the prescription. If no user id is specified, then the session user id is used.
    ///   - completion: The completion function to invoke with any error.
    public func claimPrescription(prescriptionClaim: TPrescriptionClaim, userId: String? = nil) async throws -> TPrescription {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "POST", path: "/v1/patients/\(userId ?? session.userId)/prescriptions", body: prescriptionClaim)
        return try await performRequest(request)
    }

    // MARK: - Data Sets

    /// List the data sets for the specified user id. If no user id is specified, then the session user id is used. A filter can
    /// be specified to reduce the data sets returned.
    ///
    /// - Parameters:
    ///   - filter: The filter to use when requesting the data sets.
    ///   - userId: The user id for which to get the data sets. If no user id is specified, then the session user id is used.
    ///   - completion: The completion function to invoke with any error.
    public func listDataSets(filter: TDataSet.Filter? = nil, userId: String? = nil) async throws -> [TDataSet] {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "GET", path: "/v1/users/\(userId ?? session.userId)/data_sets", queryItems: filter?.queryItems)
        return try await performRequest(request)
    }

    /// Create a data set for the specified user id. If no user id is specified, then the session user id is used.
    ///
    /// - Parameters:
    ///   - dataSet: The data set to create.
    ///   - userId: The user id for which to create the data set. If no user id is specified, then the session user id is used.
    ///   - completion: The completion function to invoke with any error.
    public func createDataSet(_ dataSet: TDataSet, userId: String? = nil) async throws -> TDataSet {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "POST", path: "/v1/users/\(userId ?? session.userId)/data_sets", body: dataSet)
        let legacyResponse: LegacyResponse.Success<TDataSet> = try await performRequest(request)
        return legacyResponse.data
    }

    // MARK: - Datum

    public typealias MalformedResult = [String: [String: Any]]
    public typealias DataResult = Result<([TDatum], MalformedResult), TError>

    /// List the data for the specified user id. If no user id is specified, then the session user id is used. A filter can
    /// be specified to reduce the data returned.
    ///
    /// - Parameters:
    ///   - filter: The filter to use when requesting the data.
    ///   - userId: The user id for which to get the data. If no user id is specified, then the session user id is used.
    /// - Returns: a tuple with the decoded data and any malformed entries
    public func listData(filter: TDatum.Filter? = nil, userId: String? = nil) async throws -> ([TDatum], MalformedResult) {
        guard let session = session else {
            throw TError.sessionMissing
        }

        let request = try createRequest(method: "GET", path: "/data/\(userId ?? session.userId)", queryItems: filter?.queryItems)
        let data: DataResponse = try await performRequest(request)
        return (data.data, data.malformed)
    }

    /// Create data for the specified data set id.
    ///
    /// - Parameters:
    ///   - data: The data to create.
    ///   - dataSetId: The data set id for which to create the data.
    public func createData(_ data: [TDatum], dataSetId: String) async throws {
        guard session != nil else {
            throw TError.sessionMissing
        }

        guard !data.isEmpty else {
            return
        }

        let request = try createRequest(method: "POST", path: "/v1/data_sets/\(dataSetId)/data", body: data)

        do {
            let _: LegacyResponse.Success<DataResponse> = try await performRequest(request)
        } catch {
            if let error = error as? TError {
                if case .requestMalformed(let response, let data) = error {
                    if let data = data {
                        if let legacyResponse = try? JSONDecoder.tidepool.decode(LegacyResponse.Failure.self, from: data) {
                            throw TError.requestMalformedJSON(response, data, legacyResponse.errors)
                        } else if let error = try? JSONDecoder.tidepool.decode(TError.Detail.self, from: data) {
                            throw TError.requestMalformedJSON(response, data, [error])
                        }
                    }
                }
            }
            throw error
        }
    }

    /// Delete data from the specified data set id.
    ///
    /// - Parameters:
    ///   - selectors: The selectors for the data to delete.
    ///   - dataSetId: The data set id from which to delete the data.
    public func deleteData(withSelectors selectors: [TDatum.Selector], dataSetId: String) async throws {
        guard session != nil else {
            throw TError.sessionMissing
        }

        guard !selectors.isEmpty else {
            return
        }
        
        let request = try createRequest(method: "DELETE", path: "/v1/data_sets/\(dataSetId)/data", body: selectors)
        try await performRequestNotDecodingResponse(request)
    }

    // MARK: - Verify Device

    /// Verify the validity of a device. Returns whether the device if is valid or not.
    ///
    /// - Parameters:
    ///   - deviceToken: The device token used to verify the validity of a device.
    /// - Returns: Whether the device is valid
    public func verifyDevice(deviceToken: Data) async throws -> Bool {
        guard session != nil else {
            throw TError.sessionMissing
        }

        let body = VerifyDeviceRequestBody(deviceToken: deviceToken.base64EncodedString())
        let request = try createRequest(method: "POST", path: "/v1/device_check/verify", body: body)

        let response: VerifyDeviceResponseBody = try await performRequest(request)
        return response.valid
    }

    struct VerifyDeviceRequestBody: Codable {
        let deviceToken: String

        private enum CodingKeys: String, CodingKey {
            case deviceToken = "device_token"
        }
    }

    struct VerifyDeviceResponseBody: Codable {
        let valid: Bool
    }

    // MARK: - Verify App

    /// Get the server challenge to be used to attest to the validity of an app instance.
    ///
    /// - Parameters:
    ///   - keyID: The key ID generated by Device Check Attestation Service.
    /// - Returns: The attestation challenge
    public func getAttestationChallenge(keyID: String) async throws -> String {
        guard session != nil else {
            throw TError.sessionMissing
        }

        let body = VerifyAppChallengeRequestBody(keyId: keyID)
        let request = try createRequest(method: "POST", path: "/v1/attestations/challenges", body: body)
        let response: VerifyAppChallengeResponseBody = try await performRequest(request)
        return response.challenge
    }

    /// Get the server challenge to be used to assert the validity of an app request.
    ///
    /// - Parameters:
    ///   - keyID: The key ID generated by Device Check Attestation Service.
    /// - returns: The assertion challenge
    public func getAssertionChallenge(keyID: String) async throws -> String {
        guard session != nil else {
            throw TError.sessionMissing
        }

        let body = VerifyAppChallengeRequestBody(keyId: keyID)
        let request = try createRequest(method: "POST", path: "/v1/assertions/challenges", body: body)
        let response: VerifyAppChallengeResponseBody = try await performRequest(request)
        return response.challenge
    }

    /// Verify the app attestation.
    ///
    /// - Parameters:
    ///   - keyID: The key ID generated by Device Check Attestation Service.
    ///   - challenge: The server provided challenge
    ///   - attestation: The attestation generated by the Device Check Attestation Service (base64 encoded)
    /// - Returns: true if the app attestation is verified
    public func verifyAttestation(keyID: String, challenge: String, attestation: String) async throws -> Bool {
        guard session != nil else {
            throw TError.sessionMissing
        }

        let body = VerifyAppAttestationVerificationRequestBody(keyId: keyID, challenge: challenge, attestation: attestation)
        let request = try createRequest(method: "POST", path: "/v1/attestations/verifications", body: body)
        try await performRequestNotDecodingResponse(request)
        return true
    }

    /// Verify the app assertion.
    ///
    /// - Parameters:
    ///   - keyID: The key ID generated by Device Check Attestation Service.
    ///   - challenge: The server provided challenge
    ///   - assertion: The assertion generated by the Device Check Attestation Service (base64 encoded)
    /// - Returns: true if the app assertion is verified
    public func verifyAssertion(keyID: String, challenge: String, assertion: String) async throws -> Bool {
        guard session != nil else {
            throw TError.sessionMissing
        }

        let body = VerifyAppAssertionVerificationRequestBody(keyId: keyID, challenge: challenge, assertion: assertion)
        let request = try createRequest(method: "POST", path: "/v1/assertions/verifications", body: body)
        try await performRequestNotDecodingResponse(request)
        return true
    }

    struct VerifyAppChallengeRequestBody: Codable {
        let keyId: String
    }

    struct VerifyAppChallengeResponseBody: Codable {
        let challenge: String
    }

    struct VerifyAppAttestationVerificationRequestBody: Codable {
        let keyId: String
        let challenge: String
        let attestation: String
    }

    struct VerifyAppAssertionVerificationRequestBody: Codable {
        let keyId: String
        let clientData: [String: String]
        let assertion: String

        init(keyId: String, challenge: String, assertion: String) {
            self.keyId = keyId
            self.clientData = ["challenge": challenge]
            self.assertion = assertion
        }
    }

    // MARK: - Internal - Create Request

    private func createRequest<E>(method: String, path: String, body: E) throws -> URLRequest where E: Encodable {
        var request = try createRequest(method: method, path: path)
        request.setValue("application/json; charset=utf-8", forHTTPHeaderField: HTTPHeaderField.contentType.rawValue)
        let encoded = try JSONEncoder.tidepool.encode(body)
        request.httpBody = encoded
        return request
    }

    private func createRequest(method: String, path: String, queryItems: [URLQueryItem]? = nil) throws -> URLRequest {
        guard let session = session else {
            throw TError.sessionMissing
        }

        var request = try createRequest(environment: session.environment, method: method, path: path, queryItems: queryItems)
        request.setValue(session.authenticationToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)
        if let trace = session.trace {
            request.setValue(trace, forHTTPHeaderField: HTTPHeaderField.tidepoolTraceSession.rawValue)
        }
        return request
    }

    private func createRequest(environment: TEnvironment, method: String, path: String, queryItems: [URLQueryItem]? = nil) throws -> URLRequest {
        let url = try environment.url(path: path, queryItems: queryItems)
        var request = URLRequest(url: url)
        request.httpMethod = method
        return request
    }

    // MARK: - Internal - Perform Request

    private typealias DecodableResult<D> = Result<D, TError> where D: Decodable

    @available(*, renamed: "performRequest(_:allowSessionRefresh:)")
    private func performRequest<D>(_ request: URLRequest?, allowSessionRefresh: Bool = true, completion: @escaping (DecodableResult<D>) -> Void) where D: Decodable {
        Task {
            do {
                let result: D = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
                completion(.success(result))
            } catch {
                completion(.failure(error as! TError))
            }
        }
    }

    private func performRequest<D>(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws -> D where D: Decodable {
        let (_, _, decoded): (HTTPURLResponse, Data?, D) = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
        return decoded
    }

    private typealias DecodableHTTPResult<D> = Result<(HTTPURLResponse, Data, D), TError> where D: Decodable

    @available(*, renamed: "performRequest(_:allowSessionRefresh:)")
    private func performRequest<D>(_ request: URLRequest?, allowSessionRefresh: Bool = true, completion: @escaping (DecodableHTTPResult<D>) -> Void) where D: Decodable {
        Task {
            do {
                let result: (HTTPURLResponse, Data, D) = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
                completion(.success(result))
            } catch {
                completion(.failure(error as! TError))
            }
        }
    }


    private func performRequest<D>(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws -> (HTTPURLResponse, Data, D) where D: Decodable {
        let (response, data) = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
        if let data = data {
            do {
                return (response, data, try JSONDecoder.tidepool.decode(D.self, from: data))
            } catch let error {
                throw TError.responseMalformedJSON(response, data, error)
            }
        } else {
            throw TError.responseMissingJSON(response)
        }
    }

    private func performRequest(_ request: URLRequest?, allowSessionRefresh: Bool = true, completion: @escaping (TError?) -> Void) {
        performRequest(request, allowSessionRefresh: allowSessionRefresh) { (result: HTTPResult) -> Void in
            switch result {
            case .failure(let error):
                completion(error)
            case .success:
                completion(nil)
            }
        }
    }

    private typealias HTTPResult = Result<(HTTPURLResponse, Data?), TError>

    @available(*, renamed: "performRequest(_:allowSessionRefresh:)")
    private func performRequest(_ request: URLRequest?, allowSessionRefresh: Bool = true, completion: @escaping (HTTPResult) -> Void) {
        Task {
            do {
                let result = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
                completion(.success(result))
            } catch {
                completion(.failure(error as! TError))
            }
        }
    }


    private func performRequest(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws -> (HTTPURLResponse, Data?) {
        if allowSessionRefresh, let session = session, session.wantsRefresh {
            return try await refreshSessionAndPerformRequest(request)
        } else {
            return try await performRequest(request, allowSessionRefreshAfterFailure: allowSessionRefresh)
        }
    }

    private func performRequestNotDecodingResponse(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws {
        if allowSessionRefresh, let session = session, session.wantsRefresh {
            let _ = try await refreshSessionAndPerformRequest(request)
        } else {
            let _ = try await performRequest(request, allowSessionRefreshAfterFailure: allowSessionRefresh)
        }
    }


    @available(*, renamed: "performRequest(_:allowSessionRefreshAfterFailure:)")
    private func performRequest(_ request: URLRequest?, allowSessionRefreshAfterFailure: Bool, completion: @escaping (HTTPResult) -> Void) {
        Task {
            do {
                let result = try await self.performRequest(request, allowSessionRefreshAfterFailure: allowSessionRefreshAfterFailure)
                completion(.success(result))
            } catch {
                completion(.failure(error as! TError))
            }
        }
    }

    private func performRequest(_ request: URLRequest?, allowSessionRefreshAfterFailure: Bool = true) async throws -> (HTTPURLResponse, Data?) {
        guard let request else {
            throw TError.requestInvalid
        }

        logging?.debug("Sending: \(request)")
        logging?.debug("Headers: \(String(describing: request.allHTTPHeaderFields))")
        if let body = request.httpBody, let bodyStr = String(data:body, encoding: .utf8) {
            logging?.debug("Body: \(bodyStr)")
        }

        let (data, response) = try await urlSession.data(for: request)

        if let response = response as? HTTPURLResponse {
            if allowSessionRefreshAfterFailure, response.statusCode == 401 {
                self.logging?.info("Refreshing session")
                return try await self.refreshSessionAndPerformRequest(request)
            } else {
                if let responseBody = String(data: data, encoding: .utf8) {
                    self.logging?.debug("Received \(responseBody)")
                }

                let statusCode = response.statusCode
                switch statusCode {
                case 200...299:
                    return (response, data)
                case 400:
                    throw TError.requestMalformed(response, data)
                case 401:
                    throw TError.requestNotAuthenticated(response, data)
                case 403:
                    throw TError.requestNotAuthorized(response, data)
                case 404:
                    throw TError.requestResourceNotFound(response, data)
                default:
                    throw TError.responseUnexpectedStatusCode(response, data)
                }
            }
        } else {
            throw TError.responseUnexpected(response, data)
        }
    }

    @available(*, renamed: "refreshSessionAndPerformRequest(_:)")
    private func refreshSessionAndPerformRequest(_ request: URLRequest?, completion: @escaping (HTTPResult) -> Void) {
        Task {
            do {
                let result = try await refreshSessionAndPerformRequest(request)
                completion(.success(result))
            } catch {
                completion(.failure(error as! TError))
            }
        }
    }

    private func refreshSessionAndPerformRequest(_ request: URLRequest?) async throws -> (HTTPURLResponse, Data?) {
        try await refreshSession()
        guard let session = self.session else {
            throw TError.sessionMissing
        }
        var request1 = request
        request1?.setValue(session.authenticationToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)
        return try await self.performRequest(request1, allowSessionRefreshAfterFailure: false)
    }

    private static var defaultUserAgent: String {
        return "\(Bundle.main.userAgent) \(Bundle(for: self).userAgent) \(ProcessInfo.processInfo.userAgent)"
    }

    private static var defaultURLSessionConfiguration: URLSessionConfiguration {
        let urlSessionConfiguration = URLSessionConfiguration.ephemeral
        if urlSessionConfiguration.httpAdditionalHeaders == nil {
            urlSessionConfiguration.httpAdditionalHeaders = [:]
        }
        urlSessionConfiguration.httpAdditionalHeaders?["User-Agent"] = TAPI.defaultUserAgent
        return urlSessionConfiguration
    }

    private var urlSessionConfigurationLocked: Locked<URLSessionConfiguration>

    private var urlSession: URLSession! {
        let urlSessionConfiguration = urlSessionConfigurationLocked.value
        return urlSessionLocked.mutate { urlSession in
            if urlSession == nil {
                urlSession = URLSession(configuration: urlSessionConfiguration)
            }
        }
    }

    private var urlSessionLocked: Locked<URLSession?>

    private var sessionLocked: Locked<TSession?>

    private static var implicitEnvironments: [TEnvironment] {
        return DNSSRVRecordsImplicit.environments
    }

    private static let DNSSRVRecordsDomainName = "environments-srv.tidepool.org"

    private static let DNSSRVRecordsImplicit = [DNSSRVRecord(priority: UInt16.min, weight: UInt16.max, host: "app.tidepool.org", port: 443)]

    private enum HTTPHeaderField: String {
        case authorization = "Authorization"
        case contentType = "Content-Type"
        case tidepoolSessionToken = "X-Tidepool-Session-Token"
        case tidepoolTraceSession = "X-Tidepool-Trace-Session"
    }
}
