import Foundation

/// Errors produced by the Aura OPAQUE protocol.
public enum OpaqueError: Error, LocalizedError, Sendable {
    /// ``OpaqueAgent/initialize()`` has not been called yet.
    case notInitialized
    /// A parameter was invalid (details in the associated string).
    case invalidInput(String)
    /// A low-level cryptographic operation failed.
    case cryptoError(String)
    /// Protocol validation failed (wrong phase or expired state).
    case validationError
    /// Authentication failed — wrong password or message tampering detected.
    case authenticationError
    /// The supplied public key is not a valid Ristretto255 point.
    case invalidPublicKey
    /// The handle has been destroyed or is otherwise unusable.
    case invalidState
    /// An unmapped native error code.
    case unknown(Int32)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "OPAQUE library not initialized. Call OpaqueAgent.initialize() first."
        case .invalidInput(let details):
            return "Invalid input: \(details)"
        case .cryptoError(let details):
            return "Cryptographic error: \(details)"
        case .validationError:
            return "Validation failed"
        case .authenticationError:
            return "Authentication failed — wrong password or message tampering detected"
        case .invalidPublicKey:
            return "Invalid public key format"
        case .invalidState:
            return "Invalid handle — may have been destroyed"
        case .unknown(let code):
            return "Unknown error (code: \(code))"
        }
    }

    internal static func fromCode(_ code: COpaqueErrorCode) -> OpaqueError {
        let raw = coOpaqueErrorCodeRawValue(code)
        let detail = coOpaqueErrorStaticMessage(code).map { String(cString: $0) } ?? "code \(raw)"
        return fromCode(raw, detail: detail)
    }

    internal static func fromCode(_ code: Int32, detail: String = "") -> OpaqueError {
        switch code {
        case  0: return .invalidState           // success returned as error is a logic bug
        case -1: return .invalidInput(detail.isEmpty ? "Invalid parameters" : detail)
        case -2: return .cryptoError(detail.isEmpty ? "Cryptographic operation failed" : detail)
        case -3: return .invalidInput(detail.isEmpty ? "Invalid protocol message" : detail)
        case -4: return .validationError
        case -5: return .authenticationError
        case -6: return .invalidPublicKey
        case -7: return .invalidInput(detail.isEmpty ? "Account already registered" : detail)
        case -8: return .cryptoError(detail.isEmpty ? "Invalid KEM input" : detail)
        case -9: return .cryptoError(detail.isEmpty ? "Invalid envelope format" : detail)
        case -10: return .invalidInput(detail.isEmpty ? "Unsupported protocol version" : detail)
        case -99:  return .cryptoError(detail.isEmpty ? "Internal FFI panic" : detail)
        case -100: return .invalidState
        default:   return .unknown(code)
        }
    }
}
