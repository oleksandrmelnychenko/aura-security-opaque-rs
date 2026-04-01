import Foundation

@_exported import EcliptixOPAQUEBinary

internal typealias COpaqueErrorCode = EcliptixOPAQUEBinary.OpaqueErrorCode

@inline(__always)
internal func coOpaqueErrorCodeRawValue(_ code: COpaqueErrorCode) -> Int32 {
    Int32(code.rawValue)
}

@inline(__always)
internal func coOpaqueErrorStaticMessage(_ code: COpaqueErrorCode) -> UnsafePointer<CChar>? {
    EcliptixOPAQUEBinary.opaque_error_string(code)
}
