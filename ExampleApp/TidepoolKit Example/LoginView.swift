//
//  LoginView.swift
//  TidepoolKit Example
//
//  Created by Pete Schwamb on 4/13/23.
//  Copyright © 2023 Tidepool Project. All rights reserved.
//

import SwiftUI
import TidepoolKit

public struct LoginView: View {

    @Environment(\.dismiss) var dismiss


    @State private var isEnvironmentActionSheetPresented = false
    @State private var message = ""
    @State private var isLoggingIn = false

    var viewModel: LoginViewModel

    public init(viewModel: LoginViewModel) {
        self.viewModel = viewModel
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
                        Text(viewModel.resolvedEnvironment.description)
                        if viewModel.loggedIn {
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
                        if viewModel.loggedIn {
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
        var buttons: [ActionSheet.Button] = viewModel.environments.map { environment in
            .default(Text(environment.description)) {
                viewModel.environment = environment
            }
        }
        buttons.append(.cancel())

        
        return ActionSheet(title: Text(NSLocalizedString("Environment", comment: "Tidepool login environment action sheet title")),
                           message: Text(viewModel.resolvedEnvironment.description), buttons: buttons)
    }

    private var messageView: some View {
        Text(message)
            .font(.callout)
            .foregroundColor(.red)
    }

    private var loginButton: some View {
        Button(action: login) {
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
            viewModel.logout()
            dismiss()
        }) {
            Text(NSLocalizedString("Logout", comment: "Tidepool logout button title"))
        }
        .buttonStyle(ActionButtonStyle(.secondary))
        .disabled(isLoggingIn)
    }

    private func login() {
        guard !isLoggingIn else {
            return
        }

        isLoggingIn = true
        viewModel.login() { error in
            setError(error)
            isLoggingIn = false
            if error == nil {
                dismiss()
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
        LoginView(viewModel: LoginViewModel(api: TAPI(clientId: "tidepool-loop", redirectURL: URL(string: "org.tidepool.Loop://tidepool_service_redirect")!)))
    }
}
