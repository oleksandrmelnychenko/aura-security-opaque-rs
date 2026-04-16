import Foundation

@_exported import AuraOPAQUEBinary

internal typealias COpaqueErrorCode = AuraOPAQUEBinary.OpaqueErrorCode

@inline(__always)
internal func coOpaqueErrorCodeRawValue(_ code: COpaqueErrorCode) -> Int32 {
    Int32(code.rawValue)
}

@inline(__always)
internal func coOpaqueErrorStaticMessage(_ code: COpaqueErrorCode) -> UnsafePointer<CChar>? {
    AuraOPAQUEBinary.opaque_error_string(code)
}
