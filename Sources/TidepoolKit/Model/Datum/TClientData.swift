//
//  TClientData.swift
//  TidepoolKit
//
//  Created by Nathaniel Hamming on 2023-09-15.
//

import Foundation

public struct TClientData: Codable {
    let challenge: String
    let partner: String
    let partnerData: [String: String]
    
    public init(challenge: String, partner: String, partnerData: [String: String]) {
        self.challenge = challenge
        self.partner = partner
        self.partnerData = partnerData
    }
}
