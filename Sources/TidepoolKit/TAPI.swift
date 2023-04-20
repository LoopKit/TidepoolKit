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
        didSet {
            urlSession = URLSession(configuration: urlSessionConfiguration)
        }
    }

    public func setURLSessionConfiguration(_ configuration: URLSessionConfiguration) {
        urlSessionConfiguration = configuration
    }

    /// The session used for all requests.
    public var session: TSession? {
        didSet {
            observers.forEach { $0.apiDidUpdateSession(self.session) }
        }
    }

    public func setSession(_ session: TSession?) {
        self.session = session
    }


    private weak var logging: TLogging?

    public func setLogging(_ newLogging: TLogging) {
        logging = newLogging
    }


    private var observers = WeakSynchronizedSet<TAPIObserver>()

    private var clientId: String

    private var redirectURL: URL

    var authorization: Authorization
    func setAuthorization(_ authorization: Authorization) {
        self.authorization = authorization
    }

    /// Create a new instance of TAPI. Automatically lookup additional environments in the background.
    ///
    /// - Parameters:
    ///   - clientId: The client id to use when authenticating
    ///   - redirectURL: The redirect url use when authenticating
    ///   - session: The initial session to use, if any.
    public init(clientId: String, redirectURL: URL, session: TSession? = nil) {
        self.clientId = clientId
        self.redirectURL = redirectURL
        self.urlSessionConfiguration = TAPI.defaultURLSessionConfiguration
        self.session = session
        self.authorization = AppAuthAuthorization()
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

    private func lookupOIDConfiguration(environment: TEnvironment) async throws -> ProviderConfiguration {

        // Lookup /info for current Tidepool environment, for issuer URL
        let info = try await getInfo(environment: environment)

        guard let issuer = info.auth?.issuerURL else {
            throw TError.missingAuthenticationIssuer
        }

        return try await getServiceConfiguration(issuer: issuer)
    }

    // MARK: - Authentication

    public func revokeTokens() async throws {
        guard let session else {
            throw TError.sessionMissing
        }

        // Lookup /info for current Tidepool environment, for issuer URL
        let info = try await getInfo(environment: session.environment)

        guard let issuer = info.auth?.issuerURL else {
            throw TError.missingAuthenticationIssuer
        }

        let config = try await getServiceConfiguration(issuer: issuer)

        guard let revokeURLStr = config.revocationEndpoint, let revokeURL = URL(string: revokeURLStr) else {
            throw TError.missingAuthenticationConfiguration
        }

        try await revokeToken(revocationURL: revokeURL, token: session.accessToken, tokenType: "access_token")

        if let refreshToken = session.refreshToken {
            try await revokeToken(revocationURL: revokeURL, token: refreshToken, tokenType: "refresh_token")
        }
    }

    private func revokeToken(revocationURL: URL, token: String, tokenType: String) async throws {

        var bodyComponents = URLComponents()
        bodyComponents.queryItems = [
            URLQueryItem(name: "token", value: token),
            URLQueryItem(name: "token_type_hint", value: tokenType),
            URLQueryItem(name: "client_id", value: clientId),
        ]

        var request = URLRequest(url: revocationURL)
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        request.httpBody = bodyComponents.query?.data(using: .utf8)

        let (data, response) = try await urlSession.data(for: request)

        guard let response = response as? HTTPURLResponse else {
            throw TError.responseUnexpected(response, data)
        }

        guard response.statusCode >= 200 && response.statusCode <= 299 else {
            throw TError.responseUnexpectedStatusCode(response, data)
        }

        // Token has successfully been
    }

    /// Login to the Tidepool environment using AppAuth (OAuth2/OpenID-Connect)
    /// used internally by the LoginSignupViewController.
    ///
    /// - Parameters:
    ///   - environment: The environment to login.
    ///   - presenting: A UIViewController to present the login modal from. Can be UIApplication.shared.windows.first!.rootViewController!
    ///   - completion: The completion function to invoke with any error.
    public func login(environment: TEnvironment, presenting: UIViewController) async throws {

        let config = try await lookupOIDConfiguration(environment: environment)

        guard let oidConfig = OIDServiceConfiguration(from: config) else {
            throw TError.missingAuthenticationConfiguration
        }

        let request = OIDAuthorizationRequest(
            configuration: oidConfig,
            clientId: self.clientId,
            clientSecret: nil,
            scopes: ["openid", "offline_access"],
            redirectURL: self.redirectURL,
            responseType: OIDResponseTypeCode,
            additionalParameters: [:]
        )

        let authState: any AuthorizationState

        do {
            authState = try await authorization.presentAuth(request: request, presenting: presenting)
        } catch {
            let authError = error as NSError
            if authError.domain == OIDGeneralErrorDomain {
                if authError.code == -3 /* OIDErrorCodeUserCanceledAuthorizationFlow */ ||
                    authError.code == -4 /* OIDErrorCodeProgramCanceledAuthorizationFlow */
                {
                    throw TError.loginCanceled
                }
            }
            throw error
        }

        guard let accessToken = authState.accessToken else
        {
            throw TError.missingAuthenticationToken
        }

        self.logging?.debug("Authorization successful, access token: \(accessToken)")

        // getAuthUser
        var userRequest = try createRequest(environment: environment, method: "GET", path: "/auth/user")
        userRequest.setValue(accessToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)

        let currentUser: TUser = try await performRequest(userRequest, allowSessionRefresh: true)

        self.session = TSession(
            environment: environment,
            accessToken: accessToken,
            accessTokenExpiration: authState.accessTokenExpirationDate,
            refreshToken: authState.refreshToken,
            userId: currentUser.userid,
            username: currentUser.username)

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
        guard let session else {
            throw TError.sessionMissing
        }

        guard let refreshToken = session.refreshToken else {
            throw TError.refreshTokenMissing
        }

        let config = try await lookupOIDConfiguration(environment: session.environment)

        guard let oidConfig = OIDServiceConfiguration(from: config) else {
            throw TError.missingAuthenticationConfiguration
        }

        let request = OIDTokenRequest(
            configuration: oidConfig,
            grantType: OIDGrantTypeRefreshToken,
            authorizationCode: nil,
            redirectURL: nil,
            clientID: self.clientId,
            clientSecret: nil,
            scope: nil,
            refreshToken: refreshToken,
            codeVerifier: nil,
            additionalParameters: nil)


        let tokenResponse = try await authorization.requestToken(request)

        if let newAccessToken = tokenResponse.accessToken {
            self.session = TSession(
                environment: session.environment,
                accessToken: newAccessToken,
                accessTokenExpiration: tokenResponse.accessTokenExpirationDate,
                refreshToken: tokenResponse.refreshToken,
                userId: session.userId,
                username: session.username)
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
        request.setValue(session.accessToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)
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

    private func performRequest<D>(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws -> D where D: Decodable {
        let (_, _, decoded): (HTTPURLResponse, Data?, D) = try await performRequest(request, allowSessionRefresh: allowSessionRefresh)
        return decoded
    }

    private typealias DecodableHTTPResult<D> = Result<(HTTPURLResponse, Data, D), TError> where D: Decodable

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

    private typealias HTTPResult = Result<(HTTPURLResponse, Data?), TError>

    private func performRequest(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws -> (HTTPURLResponse, Data?) {
        if allowSessionRefresh, let session = session, session.shouldRefresh() {
            return try await refreshSessionAndPerformRequest(request)
        } else {
            return try await performRequest(request, allowSessionRefreshAfterFailure: allowSessionRefresh)
        }
    }

    private func performRequestNotDecodingResponse(_ request: URLRequest?, allowSessionRefresh: Bool = true) async throws {
        if allowSessionRefresh, let session = session, session.shouldRefresh() {
            let _ = try await refreshSessionAndPerformRequest(request)
        } else {
            let _ = try await performRequest(request, allowSessionRefreshAfterFailure: allowSessionRefresh)
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

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            throw TError.network(error)
        }

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
                    throw TError.requestNotAuthenticated
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

    private func refreshSessionAndPerformRequest(_ request: URLRequest?) async throws -> (HTTPURLResponse, Data?) {
        do {
            try await refreshSession()
        } catch {
            let tokenError = error as NSError
            if tokenError.domain == OIDOAuthTokenErrorDomain {
                let errorCode = tokenError.userInfo[OIDOAuthErrorResponseErrorKey] ?? "unknown";
                logging?.error("Auth error while refreshing token: \(errorCode) \(error.localizedDescription)")
                self.session = nil
            } else {
                logging?.error("Error refreshing token: \(error.localizedDescription)")
            }
            throw TError.requestNotAuthenticated
        }
        guard let session = self.session else {
            throw TError.sessionMissing
        }
        var request1 = request
        request1?.setValue(session.accessToken, forHTTPHeaderField: HTTPHeaderField.tidepoolSessionToken.rawValue)
        return try await self.performRequest(request1, allowSessionRefreshAfterFailure: false)
    }

    private func getServiceConfiguration(issuer: URL) async throws -> ProviderConfiguration {

        // Lookup OpenID-Connect Service provider configuration

        let (data, response) = try await urlSession.data(from: issuer.appendingPathComponent(".well-known/openid-configuration"))

        guard let response = response as? HTTPURLResponse else {
            throw TError.responseUnexpected(response, data)
        }

        guard response.statusCode >= 200 && response.statusCode <= 299 else {
            throw TError.responseUnexpectedStatusCode(response, data)
        }

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(ProviderConfiguration.self, from: data)
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

    private var urlSession: URLSession = URLSession(configuration: defaultURLSessionConfiguration)


    private enum HTTPHeaderField: String {
        case authorization = "Authorization"
        case contentType = "Content-Type"
        case tidepoolSessionToken = "X-Tidepool-Session-Token"
        case tidepoolTraceSession = "X-Tidepool-Trace-Session"
    }
}
