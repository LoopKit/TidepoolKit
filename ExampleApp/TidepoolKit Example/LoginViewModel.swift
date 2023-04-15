//
//  LoginViewModel.swift
//  TidepoolKit Example
//
//  Created by Pete Schwamb on 4/13/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import Foundation
import TidepoolKit
import UIKit

enum LoginViewModelError: Error {
    case missingPresentingViewController
}

extension LoginViewModelError: LocalizedError {

    var errorDescription: String? {
        switch self {
        case .missingPresentingViewController:
            return NSLocalizedString("LoginViewModel was not configured correctly with a presenting ViewController.", comment: "Error description for LoginViewModelError.missingPresentingViewController")
        }
    }
}

@MainActor
public class LoginViewModel: ObservableObject {

    @Published var loggedIn: Bool = false
    @Published var environments: [TEnvironment] = []
    @Published var session: TSession?

    var resolvedEnvironment: TEnvironment {
        return selectedEnvironment ?? session?.environment ?? api.defaultEnvironment ?? environments.first!
    }

    var selectedEnvironment: TEnvironment?
    var presentingViewController: UIViewController?

    private let api: TAPI

    public init(api: TAPI) {
        self.api = api
        Task {
            session = await api.session
            loggedIn = session != nil
            environments = await api.environments
        }
    }

    func logout() async {
        await api.logout()
    }

    func login() async throws {

        guard let presentingViewController else {
            throw LoginViewModelError.missingPresentingViewController
        }

        try await api.login(environment: resolvedEnvironment, presenting: presentingViewController)
    }
}
