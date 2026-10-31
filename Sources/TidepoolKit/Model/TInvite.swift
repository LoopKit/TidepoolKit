//
//  TInvite.swift
//  TidepoolKit
//
//  Created by Pete Schwamb on 5/11/23.
//

import Foundation

public struct TInviteRequest: Codable {
    let email: String
    let nickname: String?
    let permissions: TPermissions

    public init(email: String, nickname: String?, permissions: TPermissions) {
        self.email = email
        self.nickname = nickname
        self.permissions = permissions
    }
}

public struct TInvite: Codable {
    let key: String
    let type: String
    let email: String
    let creatorId: String
    let created: Date
    let modified: Date
    // let creator: TCreator
    let status: String
}

