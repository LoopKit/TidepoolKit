//
//  Image.swift
//  TidepoolKit
//
//  Created by Rick Pasetto on 6/25/20.
//  Copyright © 2020 LoopKit Authors. All rights reserved.
//

import SwiftUI

private class LocalBundle {
    /// Returns the resource bundle associated with the current Swift module.
    static var main: Bundle = {
        if let mainResourceURL = Bundle.main.resourceURL,
           let bundle = Bundle(url: mainResourceURL.appendingPathComponent("TidepoolKit_TidepoolKit.bundle"))
        {
            return bundle
        }
        return Bundle(for: LocalBundle.self)
    }()
}

extension Image {
    init(frameworkImage name: String, decorative: Bool = false) {
        if decorative {
            self.init(decorative: name, bundle: LocalBundle.main)
        } else {
            self.init(name, bundle: LocalBundle.main)
        }
    }
}
