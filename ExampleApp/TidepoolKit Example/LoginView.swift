//
//  LoginView.swift
//  TidepoolKit Example
//
//  Created by Pete Schwamb on 4/13/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import SwiftUI
import TidepoolKit

@MainActor
public struct LoginView: View {

    @Environment(\.dismiss) var dismiss

    @State private var isEnvironmentActionSheetPresented = false
    @State private var message = ""
    @State private var isLoggingIn = false
    @State private var selectedEnvironment: TEnvironment

    var isLoggedIn: Bool
    let environments: [TEnvironment]
    let login: ((TEnvironment) async throws -> Void)?
    let logout: (() -> Void)?

    public init(
        selectedEnvironment: TEnvironment,
        isLoggedIn: Bool,
        environments: [TEnvironment],
        login: ((TEnvironment) async throws -> Void)?,
        logout: (() -> Void)?)
    {
        self._selectedEnvironment = State(initialValue: selectedEnvironment)
        self.isLoggedIn = isLoggedIn
        self.environments = environments
        self.login = login
        self.logout = logout
    }

    public var body: some View {
        ZStack {
            Color(.secondarySystemBackground)
                .edgesIgnoringSafeArea(.all)
            GeometryReader { geometry in
                ScrollView {
                    VStack {
                        HStack() {
                            Spacer()
                            closeButton
                                .padding()
                        }
                        Spacer()
                        logo
                            .padding(.horizontal, 30)
                            .padding(.bottom)
                        Text(NSLocalizedString("Environment", comment: "Label title for displaying selected Tidepool server environment."))
                            .bold()
                        Text(selectedEnvironment.description)
                        if isLoggedIn {
                            Text(NSLocalizedString("You are logged in.", comment: "LoginViewModel description text when logged in"))
                                .padding()
                        } else {
                            Text(NSLocalizedString("You are not logged in.", comment: "LoginViewModel description text when not logged in"))
                                .padding()
                        }

                        VStack(alignment: .leading) {
                            messageView
                        }
                        .padding()
                        Spacer()
                        if isLoggedIn {
                            logoutButton
                        } else {
                            loginButton
                        }
                    }
                    .padding()
                    .frame(minHeight: geometry.size.height)
                }
            }
        }
    }

    private var logo: some View {
        Image(decorative: "TidepoolLogo")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .onLongPressGesture(minimumDuration: 2) {
                UINotificationFeedbackGenerator().notificationOccurred(.warning)
                isEnvironmentActionSheetPresented = true
            }
            .actionSheet(isPresented: $isEnvironmentActionSheetPresented) { environmentActionSheet }
    }

    private var environmentActionSheet: ActionSheet {
        var buttons: [ActionSheet.Button] = environments.map { environment in
            .default(Text(environment.description)) {
                selectedEnvironment = environment
            }
        }
        buttons.append(.cancel())

        
        return ActionSheet(title: Text(NSLocalizedString("Environment", comment: "Tidepool login environment action sheet title")),
                           message: Text(selectedEnvironment.description), buttons: buttons)
    }

    private var messageView: some View {
        Text(message)
            .font(.callout)
            .foregroundColor(.red)
    }

    private var loginButton: some View {
        Button(action: {
            loginButtonTapped()
        }) {
            if isLoggingIn {
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle())
            } else {
                Text(NSLocalizedString("Login", comment: "Tidepool login button title"))
            }
        }
        .buttonStyle(ActionButtonStyle())
        .disabled(isLoggingIn)
    }


    private var logoutButton: some View {
        Button(action: {
            Task {
                logout?()
                dismiss()
            }
        }) {
            Text(NSLocalizedString("Logout", comment: "Tidepool logout button title"))
        }
        .buttonStyle(ActionButtonStyle(.secondary))
        .disabled(isLoggingIn)
    }

    private func loginButtonTapped() {
        guard !isLoggingIn else {
            return
        }

        isLoggingIn = true

        Task {
            do {
                try await login?(selectedEnvironment)
                dismiss()
            } catch {
                setError(error)
                isLoggingIn = false
            }
        }
    }

    private func setError(_ error: Error?) {
        if case .requestNotAuthenticated = error as? TError {
            self.message = NSLocalizedString("Wrong username or password.", comment: "The message for the request not authenticated error")
        } else {
            self.message = error?.localizedDescription ?? ""
        }
    }

    private var closeButton: some View {
        Button(action: { dismiss() }) {
            Text(closeButtonTitle)
                .fontWeight(.regular)
        }
    }

    private var closeButtonTitle: String { NSLocalizedString("Close", comment: "Close navigation button title of an onboarding section page view") }
}

struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView(
            selectedEnvironment: TEnvironment(host: "api.tidepool.org", port: 8888),
            isLoggedIn: false,
            environments: [],
            login: nil,
            logout: nil
        )
    }
}
