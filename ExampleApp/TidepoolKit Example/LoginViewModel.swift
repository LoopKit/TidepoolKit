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
    case configurationMissing
}

extension LoginViewModelError: LocalizedError {

    var errorDescription: String? {
        switch self {
        case .configurationMissing:
            return NSLocalizedString("View was not configured correctly.", comment: "Error description for LoginViewModelError.configurationMissing")
        }
    }
}

@MainActor
public class LoginViewModel: ObservableObject {

    var loggedIn: Bool {
        return api.session != nil
    }

    public var environment: TEnvironment?
    public var presentingViewController: UIViewController?

    private let api: TAPI

    public init(api: TAPI) {
        self.api = api
    }

    var environments: [TEnvironment] { api.environments }

    var resolvedEnvironment: TEnvironment { environment ?? api.defaultEnvironment ?? environments.first! }

    func logout() {
        api.logout()
    }

    func login() async throws {
        if let presentingViewController {
            try await api.login(environment: resolvedEnvironment, presenting: presentingViewController)
        }
        else {
            throw LoginViewModelError.configurationMissing
        }
    }
}
