//
//  Authorization.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 4/15/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import Foundation
import AppAuth


// Testing seam for OAuth2 based authentication library, AppAuth-iOS

protocol Authorization: AnyObject {
    var currentAuthorizationFlow: OIDExternalUserAgentSession? { get set }

    // Used for triggering interactive user authentication/authorization flow
    func presentAuth(request: OIDAuthorizationRequest, presenting: UIViewController) async throws -> AuthorizationState

    // Used for refreshing token
    func requestToken(_ request: OIDTokenRequest) async throws -> AuthorizationState
}

protocol AuthorizationState {
    var accessToken: String? { get }
    var accessTokenExpirationDate: Date? { get }
    var refreshToken: String? { get }
}

// Extensions for AppAuth to conform to testing seam

extension OIDAuthState: AuthorizationState {
    var accessToken: String? {
        lastTokenResponse?.accessToken
    }

    var accessTokenExpirationDate: Date? {
        lastTokenResponse?.accessTokenExpirationDate
    }
}

extension OIDTokenResponse: AuthorizationState {}


extension OIDServiceConfiguration {
    convenience init?(from config: ProviderConfiguration) {
        guard let authorizationEndpoint = URL(string: config.authorizationEndpoint),
              let tokenEndpoint = URL(string: config.tokenEndpoint),
              let issuer = URL(string: config.issuer)
        else {
            return nil
        }

        var endSessionEndpoint: URL?
        if let endSessionEndpointStr = config.endSessionEndpoint {
            endSessionEndpoint = URL(string: endSessionEndpointStr)
        } else {
            endSessionEndpoint = nil
        }

        self.init(
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint,
            issuer: issuer,
            registrationEndpoint: nil,
            endSessionEndpoint: endSessionEndpoint)
    }
}

class AppAuthAuthorization: Authorization {
    var currentAuthorizationFlow: OIDExternalUserAgentSession?

    func presentAuth(request: OIDAuthorizationRequest, presenting: UIViewController) async throws -> AuthorizationState {
        // Present the authentication session using AppAuth
        let result: (OIDAuthState, OIDExternalUserAgentSession) = try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.main.async {
                var f: OIDExternalUserAgentSession? = nil
                f = OIDAuthState.authState(byPresenting: request, presenting: presenting) { authState, error in
                    if let error = error {
                        continuation.resume(throwing: error)
                        return
                    }

                    guard let authState else {
                        continuation.resume(throwing: TError.missingAuthenticationState)
                        return
                    }

                    continuation.resume(returning: (authState, f!))
                }
            }
        }

        self.currentAuthorizationFlow = result.1
        return result.0
    }

    func requestToken(_ request: OIDTokenRequest) async throws -> AuthorizationState {
        return try await withCheckedThrowingContinuation { continuation in
            OIDAuthorizationService.perform(request) { response, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                guard let response else {
                    continuation.resume(throwing: TError.missingAuthenticationToken)
                    return
                }

                continuation.resume(returning: response)
            }
        }

    }

}
