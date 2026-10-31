//
//  OAuth2Authenticator.swift
//  
//
//  Created by Pete Schwamb on 5/1/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import Foundation
import AuthenticationServices

public protocol OAuth2AuthenticatorSessionProvider {
    func startSession(authURL: URL, callbackScheme: String?) async throws -> URL
}

// The browser sign-in sheet has no watchOS equivalent; signing in stays on the phone.
#if !os(watchOS)
@MainActor
public class ASWebAuthenticationSessionProvider: OAuth2AuthenticatorSessionProvider {

    private let contextProviding: ASWebAuthenticationPresentationContextProviding
    private var authenticationSession: ASWebAuthenticationSession?
    private var previouslyCompleted = false

    public init(contextProviding: ASWebAuthenticationPresentationContextProviding) {
        self.contextProviding = contextProviding
    }

    public func startSession(authURL: URL, callbackScheme: String?) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            self.authenticationSession = ASWebAuthenticationSession(url: authURL, callbackURLScheme: callbackScheme) { callbackURL, error in
                guard !self.previouslyCompleted else { return }
                self.previouslyCompleted = true

                if let error {
                    continuation.resume(throwing: error)
                    return
                }

                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: TError.missingAuthenticationState)
                    return
                }

                continuation.resume(returning: callbackURL)
            }
            authenticationSession?.prefersEphemeralWebBrowserSession = true
            authenticationSession?.presentationContextProvider = contextProviding
            authenticationSession?.start()
        }
    }
}
#endif

public class OAuth2Authenticator {
    private let api: TAPI
    private let environment: TEnvironment
    private var config: ProviderConfiguration?
    private var codeGenerator: CodeGenerator
    private var sessionProvider: OAuth2AuthenticatorSessionProvider

    public init(api: TAPI, environment: TEnvironment, sessionProvider: OAuth2AuthenticatorSessionProvider) {
        self.api = api
        self.environment = environment
        self.sessionProvider = sessionProvider
        self.codeGenerator = CodeGenerator()
    }

    public func login() async throws {

        let config = try await api.lookupOIDConfiguration(environment: environment)

        let redirectURL = await api.redirectURL
        let clientId = await api.clientId

        guard let scheme = redirectURL.scheme else {
            throw TError.missingAuthenticationConfiguration
        }

        guard var components = URLComponents(string: config.authorizationEndpoint) else {
            throw TError.missingAuthenticationConfiguration
        }

        let codeChallenge = codeGenerator.challenge

        components.queryItems = [
            URLQueryItem(name:"client_id", value: clientId),
            URLQueryItem(name:"redirect_uri", value: redirectURL.absoluteString),
            URLQueryItem(name:"response_type", value: "code"),
            URLQueryItem(name:"scope", value: "openid offline_access"),
            URLQueryItem(name:"code_challenge", value: codeChallenge),
            URLQueryItem(name:"code_challenge_method", value: "S256"),
        ]

        // Construct the authorization URL with PKCE parameters
        guard let authURL = components.url else {
            throw TError.missingAuthenticationConfiguration
        }

        let callbackURL: URL = try await sessionProvider.startSession(authURL: authURL, callbackScheme: scheme)
        
        guard callbackURL.getQueryParam(value: "error") == nil else {
            throw TError.authenticationError( callbackURL.getQueryParam(value: "error")!)
        }

        guard let code = callbackURL.getQueryParam(value: "code") else {
            throw TError.missingAuthenticationCode
        }

        let verifier = codeGenerator.verifier

        let tokenResponse = try await api.exchangeCodeForToken(verifier: verifier, code: code, config: config)

        try await api.createSession(
            environment: environment,
            accessToken: tokenResponse.accessToken,
            accessTokenExpiration: Date().addingTimeInterval(Double(tokenResponse.expiresIn)),
            refreshToken: tokenResponse.refreshToken)
    }
}
