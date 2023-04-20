//
//  RootTableViewController.swift
//  TidepoolKit Example
//
//  Created by Darin Krauss on 1/10/20.
//  Copyright © 2020 Tidepool Project. All rights reserved.
//

import os.log
import UIKit
import SwiftUI
import TidepoolKit


class RootTableViewController: UITableViewController, TAPIObserver {
    private let api: TAPI
    private var session: TSession? {
        didSet {
            UserDefaults.standard.session = session
            if let session = session {
                self.environment = session.environment
            } else {
                self.dataSetId = nil
            }
            updateViews()
        }
    }
    private var environment: TEnvironment? {
        didSet {
            UserDefaults.standard.environment = environment
            updateViews()
        }
    }
    private var dataSetId: String? {
        didSet {
            UserDefaults.standard.dataSetId = dataSetId
            if dataSetId == nil {
                self.datumSelectors = nil
            }
            updateViews()
        }
    }
    private var datumSelectors: [TDatum.Selector]? {
        didSet {
            updateViews()
        }
    }

    private let logging = Logging()

    required init?(coder: NSCoder) {
        self.session = UserDefaults.standard.session
        self.api = TAPI(clientId: "diy-loop", redirectURL:  URL(string: "org.loopkit.Loop://tidepool_service_redirect")!, session: session)
        self.environment = UserDefaults.standard.environment
        self.dataSetId = UserDefaults.standard.dataSetId

        super.init(coder: coder)

        Task {
            await api.setLogging(logging)
            await api.addObserver(self)
        }
    }

    func apiDidUpdateSession(_ session: TSession?) {
        self.session = session
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        tableView.register(TextButtonTableViewCell.self, forCellReuseIdentifier: TextButtonTableViewCell.className)

        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .action, target: self, action: #selector(share))

        updateViews()
    }

    private func updateViews() {
        tableView.reloadData()
        navigationItem.rightBarButtonItem?.isEnabled = session != nil
    }

    private struct SharedStatus: Codable, Equatable {
        let session: TSession
        let dataSetId: String?
    }

    @objc func share() {
        guard let session = session,
            let data = try? JSONEncoder.pretty.encode(SharedStatus(session: session, dataSetId: dataSetId)),
            let text = String(data: data, encoding: .utf8) else
        {
            return
        }
        let activityItem = UTF8TextFileActivityItem(name: "Status")
        if let error = activityItem.write(text: text) {
            present(UIAlertController(error: error), animated: true)
        } else {
            present(UIActivityViewController(activityItems: [activityItem], applicationActivities: nil), animated: true)
        }
    }

    // MARK: - UITableView

    private enum Section: Int, CaseIterable {
        case status
        case authentication
        case profile
        case dataSet
        case datum
    }

    private enum Authentication: Int, CaseIterable {
        case account
        case refresh
        case revoke
    }

    private enum Profile: Int, CaseIterable {
        case get
    }

    private enum DataSet: Int, CaseIterable {
        case list
        case create
    }

    private enum Datum: Int, CaseIterable {
        case list
        case create
        case delete
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        return Section.allCases.count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch Section(rawValue: section)! {
        case .status:
            return NSLocalizedString("Status", comment: "The title for the header of the status section")
        case .authentication:
            return NSLocalizedString("Authentication", comment: "The title for the header of the authentication section")
        case .profile:
            return NSLocalizedString("Profile", comment: "The title for the header of the profile section")
        case .dataSet:
            return NSLocalizedString("Data Set", comment: "The title for the header of the data set section")
        case .datum:
            return NSLocalizedString("Datum", comment: "The title for the header of the datum section")
        }
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        switch Section(rawValue: section)! {
        case .status:
            return 1
        case .authentication:
            return Authentication.allCases.count
        case .profile:
            return Profile.allCases.count
        case .dataSet:
            return DataSet.allCases.count
        case .datum:
            return Datum.allCases.count
        }
    }

    private let defaultStatusLabelText = NSLocalizedString("-", comment: "The default status label text")

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        switch Section(rawValue: indexPath.section)! {
        case .status:
            let cell = tableView.dequeueReusableCell(withIdentifier: StatusTableViewCell.className, for: indexPath) as! StatusTableViewCell
            cell.environmentLabel?.text = environment?.description ?? defaultStatusLabelText
            cell.authenticationTokenLabel?.text = session?.accessToken ?? defaultStatusLabelText
            cell.userIdLabel?.text = session?.userId ?? defaultStatusLabelText
            cell.dataSetIdLabel?.text = dataSetId ?? defaultStatusLabelText
            return cell
        case .authentication:
            let cell = tableView.dequeueReusableCell(withIdentifier: TextButtonTableViewCell.className, for: indexPath) as! TextButtonTableViewCell
            switch Authentication(rawValue: indexPath.row)! {
            case .account:
                cell.textLabel?.text = NSLocalizedString("Account", comment: "The text label of the account cell")
                cell.accessoryType = .disclosureIndicator
                cell.isEnabled = session == nil
            case .refresh:
                cell.textLabel?.text = NSLocalizedString("Refresh", comment: "The text label of the authentication refresh cell")
                cell.isEnabled = session != nil
            case .revoke:
                cell.textLabel?.text = NSLocalizedString("Revoke Token", comment: "The text label of the authentication revoke cell")
                cell.isEnabled = session != nil
            }
            return cell
        case .profile:
            let cell = tableView.dequeueReusableCell(withIdentifier: TextButtonTableViewCell.className, for: indexPath) as! TextButtonTableViewCell
            cell.accessoryType = .disclosureIndicator
            cell.isEnabled = session != nil
            switch Profile(rawValue: indexPath.row)! {
            case .get:
                cell.textLabel?.text = NSLocalizedString("Get Profile", comment: "The text label of the get profile cell")
            }
            return cell
        case .dataSet:
            let cell = tableView.dequeueReusableCell(withIdentifier: TextButtonTableViewCell.className, for: indexPath) as! TextButtonTableViewCell
            cell.accessoryType = .disclosureIndicator
            cell.isEnabled = session != nil
            switch DataSet(rawValue: indexPath.row)! {
            case .list:
                cell.textLabel?.text = NSLocalizedString("List Data Sets", comment: "The text label of the list data sets cell")
            case .create:
                cell.textLabel?.text = NSLocalizedString("Create Data Set", comment: "The text label of the create data set cell")
            }
            return cell
        case .datum:
            let cell = tableView.dequeueReusableCell(withIdentifier: TextButtonTableViewCell.className, for: indexPath) as! TextButtonTableViewCell
            cell.accessoryType = .disclosureIndicator
            switch Datum(rawValue: indexPath.row)! {
            case .list:
                cell.textLabel?.text = NSLocalizedString("List Data", comment: "The text label of the list data cell")
                cell.isEnabled = session != nil
            case .create:
                cell.textLabel?.text = NSLocalizedString("Create Data", comment: "The text label of the create data cell")
                cell.isEnabled = session != nil && dataSetId != nil
            case .delete:
                cell.textLabel?.text = NSLocalizedString("Delete Data", comment: "The text label of the delete data cell")
                cell.isEnabled = session != nil && dataSetId != nil && datumSelectors != nil
            }
            return cell
        }
    }

    override func tableView(_ tableView: UITableView, shouldHighlightRowAt indexPath: IndexPath) -> Bool {
        switch Section(rawValue: indexPath.section)! {
        case .status:
            return false
        case .authentication:
            switch Authentication(rawValue: indexPath.row)! {
            case .account:
                return true
            default:
                return session != nil
            }
        case .datum:
            switch Datum(rawValue: indexPath.row)! {
            case .create:
                return session != nil && dataSetId != nil
            case .delete:
                return session != nil && dataSetId != nil && datumSelectors != nil
            default:
                return session != nil
            }
        default:
            return session != nil
        }
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        switch Section(rawValue: indexPath.section)! {
        case .status:
            break
        case .authentication:
            let cell = tableView.cellForRow(at: indexPath) as! TextButtonTableViewCell
            switch Authentication(rawValue: indexPath.row)! {
            case .account:
                showAccount()
            case .refresh:
                Task {
                    cell.isLoading = true
                    await refresh()
                    cell.stopLoading()
                }
            case .revoke:
                Task {
                    cell.isLoading = true
                    await revokeToken()
                    cell.stopLoading()
                }
            }
        case .profile:
            let cell = tableView.cellForRow(at: indexPath) as! TextButtonTableViewCell
            Task {
                cell.isLoading = true
                await getProfile()
                cell.stopLoading()
            }
        case .dataSet:
            let cell = tableView.cellForRow(at: indexPath) as! TextButtonTableViewCell
            cell.isLoading = true
            Task {
                switch DataSet(rawValue: indexPath.row)! {
                case .list:
                    await listDataSets()
                case .create:
                    await createDataSet()
                }
                cell.stopLoading()
            }
        case .datum:
            let cell = tableView.cellForRow(at: indexPath) as! TextButtonTableViewCell
            cell.isLoading = true
            Task {
                switch Datum(rawValue: indexPath.row)! {
                case .list:
                    await listData()
                case .create:
                    await createData()
                case .delete:
                    await deleteData()
                }
                cell.stopLoading()
            }
        }
        tableView.deselectRow(at: indexPath, animated: true)
    }

    // MARK: - Authentication
    private var loginPresentingViewController: UIViewController {
        return self.presentedViewController ?? self
    }

    private func showAccount() {
        Task {
            let environments = try await TEnvironment.fetchEnvironments()
            let currentEnvironment = self.session?.environment ?? self.api.defaultEnvironment ?? environments.first!
            let view = LoginView(
                selectedEnvironment: currentEnvironment,
                isLoggedIn: session != nil,
                environments: environments) { environment throws in
                    try await self.api.login(environment: environment, presenting: self.loginPresentingViewController)
                } logout: {
                    Task {
                        await self.api.logout()
                    }
                }

            let loginViewController = UIHostingController(rootView: view)
            present(loginViewController, animated: true)
        }
    }

    private func refresh() async {
        do {
            try await api.refreshSession()
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    private func revokeToken() async {
        do {
            try await api.revokeTokens()
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }


    private func logout() async {
        await api.logout()
    }

    // MARK: - Profile

    private func getProfile() async {
        do {
            let profile = try await api.getProfile()
            self.display(profile, withTitle: "Get Profile")
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    // MARK: - Data Set

    private func listDataSets() async {
        let filter = TDataSet.Filter(clientName: Bundle.main.bundleIdentifier)
        do {
            let dataSets = try await api.listDataSets(filter: filter)
            self.dataSetId = dataSets.first?.uploadId
            self.display(dataSets, withTitle: "List Data Sets")
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    private func createDataSet() async {
        let client = TDataSet.Client(name: Bundle.main.bundleIdentifier!, version: Bundle.main.semanticVersion!)
        let deduplicator = TDataSet.Deduplicator(name: .none)
        let dataSet = TDataSet(dataSetType: .continuous, client: client, deduplicator: deduplicator)
        do {
            let dataSet = try await api.createDataSet(dataSet)
            self.dataSetId = dataSet.uploadId
            self.display(dataSet, withTitle: "Create Data Set")
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    // MARK: - Datum

    private func listData() async {
        let filter = TDatum.Filter(dataSetId: dataSetId)
        do {
            let (data, malformed) = try await api.listData(filter: filter)
            if !malformed.isEmpty {
                self.present(UIAlertController(error: "Response contains malformed data.") {
                    self.display(malformed, withTitle: "MALFORMED - List Data")
                }, animated: true)
            } else {
                self.display(data, withTitle: "List Data")
            }
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    private func createData() async {
        let data = Sample.Datum.data()
        do {
            try await api.createData(data, dataSetId: dataSetId!)
        } catch {
            if let error = error as? TError {
                if case .requestMalformedJSON(_, _, let errors) = error {
                    self.present(UIAlertController(error: "Request contains errors.") {
                        self.display(errors, withTitle: "ERRORS - Create Data")
                    }, animated: true)
                } else {
                    self.present(UIAlertController(error: error), animated: true)
                }
            } else {
                self.datumSelectors = data.compactMap { $0.selector }
            }
        }
    }

    private func deleteData() async {
        do {
            try await api.deleteData(withSelectors: datumSelectors!, dataSetId: dataSetId!)
            self.datumSelectors = nil
        } catch {
            self.present(UIAlertController(error: error), animated: true)
        }
    }

    // MARK: - Internal

    private func display<E>(_ encodable: E, withTitle title: String? = nil) where E: Encodable {
        do {
            display(try JSONEncoder.pretty.encode(encodable), withTitle: title)
        } catch let error {
            logging.error("Failure to encode object as JSON data [\(error)]")
            present(UIAlertController(error: "Failure to encode object as JSON data."), animated: true)
        }
    }

    private func display(_ object: Any, withTitle title: String? = nil) {
        do {
            display(try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), withTitle: title)
        } catch let error {
            logging.error("Failure to encode object as JSON data [\(error)]")
            present(UIAlertController(error: "Failure to encode object as JSON data."), animated: true)
        }
    }

    private func display(_ data: Data, withTitle title: String? = nil) {
        guard let text = String(data: data, encoding: .utf8) else {
            present(UIAlertController(error: "Failure to decode JSON data as string."), animated: true)
            return
        }
        show(TextViewController(text: text, withTitle: title), sender: self)
    }
}
