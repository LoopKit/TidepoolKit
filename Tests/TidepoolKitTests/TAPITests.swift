//
//  TAPITests.swift
//  TidepoolKitTests
//
//  Created by Darin Krauss on 3/3/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import XCTest
import AppAuth
@testable import TidepoolKit


class TAPITests: XCTestCase {
    var api: TAPI!
    var environment: TEnvironment!
    let accessToken = randomString
    let refreshToken = randomString
    let userId = randomString

    override func setUp() async throws {
        try await super.setUp()

        URLProtocolMock.handlers = []

        self.api = TAPI(clientId: "test", redirectURL: URL(string: "org.tidepool.TidepoolKit://redirect")!)
        let urlSessionConfiguration = await api.urlSessionConfiguration
        urlSessionConfiguration.protocolClasses = [URLProtocolMock.self]
        await self.api.setURLSessionConfiguration(urlSessionConfiguration)
        self.environment = TEnvironment(host: "test.org", port: 443)
    }

    override func tearDown() {
        XCTAssertTrue(URLProtocolMock.handlers.isEmpty, "Unused handlers at end of test (first = \(URLProtocolMock.handlers[0]). Tests should use all configured handlers")
    }

    static var randomString: String { UUID().uuidString }

    struct TestError: Error {}

    func setUpNetworkError() {
        URLProtocolMock.handlers[0].error = TestError()
    }

    func setUpRequestNotAuthenticated() async {
        // Sets up the first api request to fail with a 401, and then returns a failure on the token refresh as well
        let authorization = MockAuthorization()
        authorization.refreshTokenError = MockAuthorization.tokenAccessDeniedError
        await api.setAuthorization(authorization)
        URLProtocolMock.handlers[0].success?.statusCode = 401
    }

    func setUpRequestNotAuthorized() {
        URLProtocolMock.handlers[0].success?.statusCode = 403
    }

    func setUpResponseNotAuthenticated() {
        URLProtocolMock.handlers[0].success?.headers = nil
    }

    func setUpResponseMalformedJSON() {
        URLProtocolMock.handlers[0].success?.body = nil
    }
}

class TAPIURLSessionConfigurationTests: TAPITests {
    func testDefaultURLSessionConfiguration() async {
        let urlSessionConfiguration = await api.urlSessionConfiguration
        XCTAssertNotNil(urlSessionConfiguration.httpAdditionalHeaders)
        XCTAssertNotNil(urlSessionConfiguration.httpAdditionalHeaders?["User-Agent"])
        XCTAssertNotNil(urlSessionConfiguration.protocolClasses)
    }
}

class TAPIInfoTests: TAPITests {

    static let info = TInfo(
        versions: TInfo.Versions(loop: TInfo.Versions.Loop(minimumSupported: "1.2.3", criticalUpdateNeeded: ["1.0.0", "1.1.0"])),
        auth: TInfo.Auth(realm: "testrealm", url: "https://test.org/authurl")
    )
    
    override func setUp() {
        super.setUp()

        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/info", method: "GET"),
                                                            success: URLProtocolMock.Success(statusCode: 200, body: TAPIInfoTests.info))]
    }

    func testNetworkError() async {
        setUpNetworkError()

        do {
            let _ = try await api.getInfo(environment: environment)
            XCTFail()
        } catch {
            guard case TError.network(let networkError) = error else {
                XCTFail(String(describing: error))
                return
            }
            XCTAssertNotNil(networkError)
        }
    }

    func testRequestNotAuthenticated() async {
        await setUpRequestNotAuthenticated()

        do {
            let _ = try await api.getInfo(environment: environment)
            XCTFail()
        } catch {
            guard case TError.requestNotAuthenticated = error else {
                XCTFail()
                return
            }
        }
    }

    func testRequestNotAuthorized() async {
        setUpRequestNotAuthorized()

        do {
            let _ = try await api.getInfo(environment: environment)
            XCTFail()
        } catch {
            guard case TError.requestNotAuthorized = error else {
                XCTFail()
                return
            }
        }
    }

    func testResponseMalformedJSON() async {
        setUpResponseMalformedJSON()

        do {
            let _ = try await api.getInfo(environment: environment)
            XCTFail()
        } catch {
            guard case TError.responseMalformedJSON = error else {
                XCTFail()
                return
            }
        }
    }

    func testSuccess() async {
        do {
            let info = try await api.getInfo(environment: environment)
            XCTAssertEqual(info, TAPIInfoTests.info)
        } catch {
            XCTFail()
        }
    }

    func testSuccessUsingSessionEnvironment() async {
        let env = TEnvironment(host: "foo.bar.baz", port: 123)
        let session = TSession(environment: env, accessToken: accessToken, accessTokenExpiration: nil, refreshToken: nil, userId: userId, username: "test@test.com")

        await api.setSession(session)

        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "http://foo.bar.baz:123/info", method: "GET"),
                                                            success: URLProtocolMock.Success(statusCode: 200, body: TAPIInfoTests.info))]

        do {
            let info = try await api.getInfo(environment: env)
            XCTAssertEqual(info, TAPIInfoTests.info)
        } catch {
            XCTFail()
        }
    }
    
}

extension OIDServiceConfiguration {
    static var mock: OIDServiceConfiguration {
        return OIDServiceConfiguration(authorizationEndpoint: URL(string: "http://auth.bar.baz:123/auth")!, tokenEndpoint: URL(string: "http://auth.bar.baz:123/token")!)
    }
}

class MockAuthorization: Authorization {

    static var tokenAccessDeniedError = NSError(domain: OIDOAuthTokenErrorDomain, code: -4)

    var currentAuthorizationFlow: OIDExternalUserAgentSession?
    var lastAuthRequest: OIDAuthorizationRequest?
    var loginFailureError: Error?

    var lastTokenRequest: OIDTokenRequest?
    var refreshTokenError: Error?

    var accessTokenExpirationDate: Date?

    func getServiceConfiguration(issuer: URL) async throws -> OIDServiceConfiguration {
        return OIDServiceConfiguration.mock
    }

    func presentAuth(request: OIDAuthorizationRequest, presenting: UIViewController) async throws -> AuthorizationState {
        lastAuthRequest = request
        if let loginFailureError {
            throw loginFailureError
        }
        let authorizationResponse = MockAuthorizationResponse(
            accessToken: "mockAccessToken",
            accessTokenExpirationDate: accessTokenExpirationDate,
            refreshToken: "mockRefreshToken")
        return authorizationResponse
    }

    func requestToken(_ request: OIDTokenRequest) async throws -> AuthorizationState {
        lastTokenRequest = request

        if let refreshTokenError {
            throw refreshTokenError
        }

        let authorizationResponse = MockAuthorizationResponse(
            accessToken: "refreshedAccessToken",
            accessTokenExpirationDate: accessTokenExpirationDate,
            refreshToken: "refreshedRefreshToken")
        return authorizationResponse

    }
}

struct MockAuthorizationResponse: AuthorizationState {
    var accessToken: String?

    var accessTokenExpirationDate: Date?

    var refreshToken: String?
}

class TAPISessionTests: TAPITests {
    var session: TSession!
    var headers: [String: String]!
    var authorization: MockAuthorization!

    static var mockUser: TUser {
        return TUser(
            emailVerified: true,
            emails: ["name@email.org"],
            roles: ["default-roles-integration", "patient"],
            termsAccepted: Date(),
            userid: "e631fc5a-1234-4686-a498-8f2bbfec55b6",
            username: "name@email.org")
    }

    static var mockOIDCConfig: ProviderConfiguration {
        return ProviderConfiguration(
            issuer: "https://test.org/authurl/realms/testrealm/",
            authorizationEndpoint: "https://test.org/authurl/realms/testrealm/auth",
            tokenEndpoint: "https://test.org/authurl/realms/testrealm/token")
    }

    let authConfigHandler = URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/authurl/realms/testrealm/.well-known/openid-configuration", method: "GET"), success: URLProtocolMock.Success(statusCode: 200, body: mockOIDCConfig))

    let environmentInfoHandler = URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/info", method: "GET"), success: URLProtocolMock.Success(statusCode: 200, body: TAPIInfoTests.info))
    
    let userHandler = URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/auth/user", method: "GET"), success: URLProtocolMock.Success(statusCode: 200, body: TAPILoginTests.mockUser))


    override func setUp() async throws {
        try await super.setUp()

        session = TSession(environment: environment, accessToken: accessToken, accessTokenExpiration: nil, refreshToken: refreshToken, userId: userId, username: "test@test.com")
        headers = ["X-Tidepool-Session-Token": accessToken, "X-Tidepool-Trace-Session": session.trace!]
        await api.setSession(session)
        authorization = MockAuthorization()
        await api.setAuthorization(authorization)

    }
}

class TAPILoginTests: TAPISessionTests {

    override func setUp() async throws {
        try await super.setUp()
    }


    func testSuccessfulLogin() async {
        let mockUIViewController = await UIViewController()
        do {
            URLProtocolMock.handlers = [environmentInfoHandler, authConfigHandler, userHandler]

            try await api.login(environment: session.environment, presenting: mockUIViewController)

            XCTAssertEqual(authorization.lastAuthRequest?.clientID, "test")
            XCTAssertEqual(authorization.lastAuthRequest?.redirectURL, URL(string: "org.tidepool.TidepoolKit://redirect"))
            XCTAssertEqual(authorization.lastAuthRequest?.scope, "openid offline_access")

            let session = await api.session
            XCTAssertEqual(session?.accessToken, "mockAccessToken")
            XCTAssertEqual(session?.accessTokenExpiration, nil)
            XCTAssertEqual(session?.refreshToken, "mockRefreshToken")
        } catch {
            XCTFail(String(describing: error))
        }
    }

    func testFailedLogin() async {
        URLProtocolMock.handlers = [environmentInfoHandler, authConfigHandler]
        let mockUIViewController = await UIViewController()
        do {
            authorization.loginFailureError = TError.missingAuthenticationState
            await api.setSession(nil)

            try await api.login(environment: session.environment, presenting: mockUIViewController)
            XCTFail("Login should not succeed")
        } catch {
            let session = await api.session
            XCTAssertNil(session)
        }
    }

    func testSessionRefresh() async {
        do {
            URLProtocolMock.handlers = [environmentInfoHandler, authConfigHandler]
            let newExpiration = Date().addingTimeInterval(12 * 60 * 60)
            authorization.accessTokenExpirationDate = newExpiration
            try await api.refreshSession()

            let session = await api.session

            XCTAssertEqual(authorization.lastTokenRequest?.clientID, "test")
            XCTAssertEqual(authorization.lastTokenRequest?.redirectURL, nil)
            XCTAssertEqual(authorization.lastTokenRequest?.scope, nil)

            XCTAssertEqual(session?.accessToken, "refreshedAccessToken")
            XCTAssertEqual(session?.accessTokenExpiration, newExpiration)
            XCTAssertEqual(session?.refreshToken, "refreshedRefreshToken")
        } catch {
            XCTFail(String(describing: error))
        }
    }

    func testRefreshTriggeredWhenPastExpiration() async {

        let refreshedAccessToken = "refreshedAccessToken"

        let headers = ["X-Tidepool-Session-Token": refreshedAccessToken, "X-Tidepool-Trace-Session": session.trace!]

        URLProtocolMock.handlers = [
            environmentInfoHandler,
            authConfigHandler,
            URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/metadata/\(userId)/profile", method: "GET", headers: headers), success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: TProfileTests.profile))
        ]

        let expiredSession = TSession(
            environment: session.environment,
            accessToken: session.accessToken,
            accessTokenExpiration: Date().addingTimeInterval(-30),
            refreshToken: session.refreshToken,
            userId: session.userId,
            username: session.username,
            trace: session.trace
        )

        await api.setSession(expiredSession)

        // Make a profile request

        do {
            let profile = try await api.getProfile(userId: session.userId)

            XCTAssertEqual(profile, TProfileTests.profile)

            XCTAssertNotNil(authorization.lastTokenRequest)
            let refreshedSession = await api.session
            XCTAssertEqual(refreshedSession?.accessToken, refreshedAccessToken)

        } catch {
            XCTFail(String(describing: error))
        }

    }

    func textRefreshTriggeredWhenAPIReturnsAuthenticationError() async {
        // Should refresh on both 401 and 403, I think
        XCTFail("TODO")
    }

}


class TAPIGetProfileTests: TAPISessionTests {

    var getProfileHandler: URLProtocolMock.Handler!

    override func setUp() async throws {
        try await super.setUp()

        getProfileHandler = URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/metadata/\(userId)/profile", method: "GET", headers: headers), success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: TProfileTests.profile))
    }

    func testNetworkError() async {
        URLProtocolMock.handlers = [getProfileHandler]
        setUpNetworkError()

        do {
            let _ = try await api.getProfile()
            XCTFail("Request should have failed")
        } catch {
            guard case TError.network(let networkError) = error else {
                XCTFail()
                return
            }
            XCTAssertNotNil(networkError)
        }
    }

    func testRequestNotAuthenticated() async {
        URLProtocolMock.handlers = [getProfileHandler, environmentInfoHandler, authConfigHandler]
        await setUpRequestNotAuthenticated()

        do {
            let _ = try await api.getProfile()
            XCTFail("Request should have failed")
        } catch {
            guard case TError.requestNotAuthenticated = error else {
                XCTFail(String(describing: error))
                return
            }
        }
    }

    func testRequestNotAuthorized() async {

        URLProtocolMock.handlers = [getProfileHandler]

        setUpRequestNotAuthorized()

        do {
            let _ = try await api.getProfile()
            XCTFail("Request should have failed")
        } catch {
            guard case TError.requestNotAuthorized = error else {
                XCTFail()
                return
            }
        }
    }

    func testResponseMalformedJSON() async {
        URLProtocolMock.handlers = [getProfileHandler]

        setUpResponseMalformedJSON()

        do {
            let _ = try await api.getProfile()
            XCTFail("Request should have failed")
        } catch {
            guard case TError.responseMalformedJSON = error else {
                XCTFail()
                return
            }
        }
    }

    func testSuccess() async {
        URLProtocolMock.handlers = [getProfileHandler]

        do {
            let profile = try await api.getProfile()
            XCTAssertEqual(profile, TProfileTests.profile)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIClaimPrescriptionTests: TAPISessionTests {
    var prescriptionClaim: TPrescriptionClaim!

    override func setUp() {
        super.setUp()

        prescriptionClaim = TPrescriptionClaim(accessCode: "ABCDEF", birthday: "2004-01-04")
        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/patients/\(userId)/prescriptions", method: "POST", headers: headers, body: prescriptionClaim),
                                                            success: URLProtocolMock.Success(statusCode: 201, headers: headers, body: TPrescriptionTests.prescription))]
    }

    func testSuccess() async {
        do {
            let claimedPrescription = try await api.claimPrescription(prescriptionClaim: prescriptionClaim)
            XCTAssertEqual(claimedPrescription, TPrescriptionTests.prescription)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIListDataSetsTests: TAPISessionTests {
    override func setUp() {
        super.setUp()

        let url = "https://test.org/v1/users/\(userId)/data_sets?client.name=org.tidepool.Example&deleted=true&deviceId=ExampleDeviceId"
        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: url, method: "GET", headers: headers),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: [TDataSetTests.dataSet]))]
    }

    func testSuccess() async {
        do {
            let dataSets = try await api.listDataSets(filter: TDataSetFilterTests.filter)
            XCTAssertEqual(dataSets, [TDataSetTests.dataSet])
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPICreateDataSetTests: TAPISessionTests {
    var dataSet: TDataSet!

    override func setUp() {
        super.setUp()

        dataSet = TDataSet(dataSetType: .continuous, client: TDataSetClientTests.client, deduplicator: TDataSet.Deduplicator(name: .dataSetDeleteOrigin))
        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/users/\(userId)/data_sets", method: "POST", headers: headers, body: dataSet),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: LegacyResponse.Success(data: TDataSetTests.dataSet)))]
    }

    func testSuccess() async {
        do {
            let createdDataSet = try await api.createDataSet(dataSet)
            XCTAssertEqual(createdDataSet, TDataSetTests.dataSet)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIListDataTests: TAPISessionTests {
    override func setUp() {
        super.setUp()

        let url = "https://test.org/data/\(userId)?startDate=\(Date.testJSONString)"
        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: url, method: "GET", headers: headers),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: [TCBGDatumTests.cbg, TFoodDatumTests.food]))]
    }

    func testSuccess() async {
        do {
            let (data, malformed) = try await api.listData(filter: TDatum.Filter(startDate: Date.test))
            XCTAssertEqual(data, [TCBGDatumTests.cbg, TFoodDatumTests.food])
            XCTAssertEqual(malformed.count, 0)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPICreateDataTests: TAPISessionTests {
    let dataSetId = randomString
    let data = [TCBGDatumTests.cbg, TFoodDatumTests.food]

    override func setUp() {
        super.setUp()

        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/data_sets/\(dataSetId)/data", method: "POST", headers: headers, body: data),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: LegacyResponse.Success<DataResponse>(data: DataResponse())))]
    }

    func testRequestMalformedJSON() async {
        let errors = [TError.Detail(code: "code-123", title: "title-123", detail: "detail-123"),
                      TError.Detail(code: "code-456", title: "title-456", detail: "detail-456"),
                      TError.Detail(code: "code-789", title: "title-789", detail: "detail-789")]
        URLProtocolMock.handlers[0].success = URLProtocolMock.Success(statusCode: 400, headers: headers, body: LegacyResponse.Failure(errors: errors))

        do {
            try await api.createData(data, dataSetId: dataSetId)
            XCTFail()
        } catch {
            guard case TError.requestMalformedJSON(_, _, let malformedJSONErrors) = error else {
                XCTFail()
                return
            }
            XCTAssertEqual(malformedJSONErrors, errors)
        }
    }

    func testSuccess() async {
        do {
            try await api.createData(data, dataSetId: dataSetId)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIDeleteDataTests: TAPISessionTests {
    let dataSetId = randomString
    let selectors = [TDatum.Selector(id: randomString), TDatum.Selector(origin: TDatum.Selector.Origin(id: randomString))]

    override func setUp() {
        super.setUp()

        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/data_sets/\(dataSetId)/data", method: "DELETE", headers: headers, body: selectors),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: LegacyResponse.Success<DataResponse>(data: DataResponse())))]
    }

    func testSuccess() async {
        do {
            try await api.deleteData(withSelectors: selectors, dataSetId: dataSetId)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIVerifyDeviceTests: TAPISessionTests {
    let deviceToken = randomString.data(using: .utf8)!

    override func setUp() {
        super.setUp()

        let body = TAPI.VerifyDeviceRequestBody(deviceToken: deviceToken.base64EncodedString())
        URLProtocolMock.handlers = [URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/device_check/verify", method: "POST", headers: headers, body: body),
                                                            success: URLProtocolMock.Success(statusCode: 200, headers: headers, body: TAPI.VerifyDeviceResponseBody(valid: true)))]
    }

    func testSuccess() async {
        do {
            let valid = try await api.verifyDevice(deviceToken: deviceToken)
            XCTAssertTrue(valid)
        } catch {
            XCTFail(String(describing: error))
        }
    }

    func testSuccessInvalid() async {
        URLProtocolMock.handlers[0].success = URLProtocolMock.Success(statusCode: 200, headers: headers, body: TAPI.VerifyDeviceResponseBody(valid: false))

        do {
            let valid = try await api.verifyDevice(deviceToken: deviceToken)
            XCTAssertFalse(valid)
        } catch {
            XCTFail(String(describing: error))
        }
    }
}

class TAPIVerifyAppTests: TAPISessionTests {
    let challenge = randomString
    let attestationKeyID = randomString
    let attestationEncoded = randomString.data(using: .utf8)!.base64EncodedString()
    let assertionEncoded = randomString.data(using: .utf8)!.base64EncodedString()

    func testSuccessChallengeAttestation() async throws {
        let challengeRequestBody = TAPI.VerifyAppChallengeRequestBody(keyId: attestationKeyID)
        URLProtocolMock.handlers.append(URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/attestations/challenges", method: "POST", headers: headers, body: challengeRequestBody),
                                                                success: URLProtocolMock.Success(statusCode: 201, headers: headers, body: TAPI.VerifyAppChallengeResponseBody(challenge: challenge))))

        let challenge = try await api.getAttestationChallenge(keyID: attestationKeyID)
        XCTAssertEqual(challenge, self.challenge)
    }

    func testSuccessChallengeAssertion() async throws {
        let challengeRequestBody = TAPI.VerifyAppChallengeRequestBody(keyId: attestationKeyID)
        URLProtocolMock.handlers.append(URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/assertions/challenges", method: "POST", headers: headers, body: challengeRequestBody),
                                                                success: URLProtocolMock.Success(statusCode: 201, headers: headers, body: TAPI.VerifyAppChallengeResponseBody(challenge: challenge))))

        let challenge = try await api.getAssertionChallenge(keyID: attestationKeyID)
        XCTAssertEqual(challenge, self.challenge)
    }

    func testSuccessAttestation() async throws {
        let attestationRequestBody = TAPI.VerifyAppAttestationVerificationRequestBody(keyId: attestationKeyID, challenge: challenge, attestation: attestationEncoded)
        URLProtocolMock.handlers.append(URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/attestations/verifications", method: "POST", headers: headers, body: attestationRequestBody),
                                                                success: URLProtocolMock.Success(statusCode: 204, headers: headers)))

        let valid = try await api.verifyAttestation(keyID: attestationKeyID, challenge: challenge, attestation: attestationEncoded)
        XCTAssertTrue(valid)
    }

    func testSuccessAssertion() async throws {
        let assertionRequestBody = TAPI.VerifyAppAssertionVerificationRequestBody(keyId: attestationKeyID, challenge: challenge, assertion: assertionEncoded)
        URLProtocolMock.handlers.append(URLProtocolMock.Handler(validator: URLProtocolMock.Validator(url: "https://test.org/v1/assertions/verifications", method: "POST", headers: headers, body: assertionRequestBody),
                                                                 success: URLProtocolMock.Success(statusCode: 204, headers: headers)))

        let valid = try await api.verifyAssertion(keyID: attestationKeyID, challenge: challenge, assertion: assertionEncoded)
        XCTAssertTrue(valid)
    }
}
