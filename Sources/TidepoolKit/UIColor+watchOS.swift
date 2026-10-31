//
//  UIColor+watchOS.swift
//  TidepoolKit
//
//  watchOS has no system background colours. The package's SwiftUI styles name two; on the watch
//  they stand in as black, its background. The styles belong to the iOS sign-in screens.
//

#if os(watchOS)
import UIKit

extension UIColor {
    static var secondarySystemBackground: UIColor { .black }
    static var systemGroupedBackground: UIColor { .black }
}
#endif
