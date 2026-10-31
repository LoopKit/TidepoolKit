//
//  TPendingInvite.swift
//  TidepoolKit
//
//  Created by Arwain Karlin on 6/5/23.
//

import Foundation

public struct TPendingInvite: Codable, Equatable {
    public let key: String
    public let type: String
    public let status: String
    public let email: String
    public let context: TPendingInviteContext?
    public let created: Date
    public let modified: Date
    public let expiresAt: Date?
    public let creator: TCreator
    
    init(
        key: String,
        type: String,
        status: String,
        email: String,
        context: TPendingInviteContext?,
        created: Date,
        modified: Date,
        expiresAt: Date?,
        creator: TCreator
    ) {
        self.key = key
        self.type = type
        self.status = status
        self.email = email
        self.context = context
        self.created = created
        self.modified = modified
        self.expiresAt = expiresAt
        self.creator = creator
    }
}

public struct TPendingInviteContext: Codable, Equatable {
    public let nickname: String?
    public let permissions: TPermissions?
    
    init(
        nickname: String?,
        permissions: TPermissions?
    ) {
        self.nickname = nickname
        self.permissions = permissions
    }
}
