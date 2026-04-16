import Foundation

/// Client-side handle for the Aura Hybrid PQ-OPAQUE protocol.
///
/// `OpaqueAgent` wraps the Rust FFI and provides a safe Swift interface for
/// password registration and authentication using a hybrid post-quantum OPAQUE
/// protocol (4-DH Ristretto255 + ML-KEM-768).
///
/// ## Quick Start
///
/// ```swift
/// // One-time initialization
/// try OpaqueAgent.initialize()
///
/// let agent = try OpaqueAgent(relayPublicKey: serverPublicKey)
///
/// // --- Registration (one-time per account) ---
/// let state = try agent.createState()
/// let request = try agent.createRegistrationRequest(password: pwd, state: state)
/// // send request → server, receive response
/// let record = try agent.finalizeRegistration(response: response, state: state)
/// // send record → server for storage
/// state.dispose()
///
/// // --- Authentication (each login) ---
/// let loginState = try agent.createState()
/// let ke1 = try agent.generateKE1(password: pwd, accountId: accountId, state: loginState)
/// // send ke1 → server, receive ke2
/// let ke3 = try agent.generateKE3(ke2: ke2, state: loginState)
/// // send ke3 → server
/// let keys = try agent.finish(state: loginState)
/// // use keys.withSessionKey { ... }
/// keys.dispose()
/// loginState.dispose()
/// ```
public final class OpaqueAgent: @unchecked Sendable {

    // Swift imports pointers to incomplete C struct types as OpaquePointer.
    private var handle: OpaquePointer?
    private let lock = NSLock()

    private nonisolated(unsafe) static var isInitialized = false
    private static let initLock = NSLock()

    /// Initializes the underlying cryptographic library.
    ///
    /// Must be called once before creating any `OpaqueAgent` instances.
    /// Safe to call multiple times — subsequent calls are no-ops.
    public static func initialize() throws {
        initLock.lock()
        defer { initLock.unlock() }

        if isInitialized { return }

        let result = opaque_init()
        guard result.rawValue == 0 else {
            throw OpaqueError.cryptoError(
                "Failed to initialize cryptographic library (code: \(result.rawValue))"
            )
        }

        isInitialized = true

        precondition(opaque_get_ke1_length() == Constants.ke1Length,
                     "KE1 length mismatch: Swift=\(Constants.ke1Length), Rust=\(opaque_get_ke1_length())")
        precondition(opaque_get_ke2_length() == Constants.ke2Length,
                     "KE2 length mismatch: Swift=\(Constants.ke2Length), Rust=\(opaque_get_ke2_length())")
        precondition(opaque_get_ke3_length() == Constants.ke3Length,
                     "KE3 length mismatch: Swift=\(Constants.ke3Length), Rust=\(opaque_get_ke3_length())")
        precondition(opaque_get_registration_record_length() == Constants.registrationRecordLength,
                     "Registration record length mismatch")
    }

    internal static var initialized: Bool {
        initLock.lock()
        defer { initLock.unlock() }
        return isInitialized
    }

    /// Creates a new agent bound to a relay's static public key.
    ///
    /// - Parameter relayPublicKey: The relay's 32-byte Ristretto255 public key.
    /// - Throws: ``OpaqueError/notInitialized``, ``OpaqueError/invalidPublicKey``.
    public init(relayPublicKey: Data) throws {
        guard Self.initialized else {
            throw OpaqueError.notInitialized
        }
        guard relayPublicKey.count == Constants.publicKeyLength else {
            throw OpaqueError.invalidInput(
                "Relay public key must be \(Constants.publicKeyLength) bytes"
            )
        }

        var rawHandle: OpaquePointer?
        let result = relayPublicKey.withUnsafeBytes { keyPtr in
            opaque_agent_create(
                keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                relayPublicKey.count,
                &rawHandle
            )
        }

        guard result.rawValue == 0, let h = rawHandle else {
            throw OpaqueError.fromCode(result)
        }
        self.handle = h
    }

    deinit {
        lock.lock()
        var h: OpaquePointer? = handle
        handle = nil
        lock.unlock()
        if h != nil {
            opaque_agent_destroy(&h)
        }
    }

    /// Creates a fresh protocol state for one registration or authentication session.
    public func createState() throws -> AgentState {
        try AgentState()
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// **Registration step 1/2.** Creates an OPRF-blinded registration request (33 bytes).
    public func createRegistrationRequest(password: Data, state: AgentState) throws -> Data {
        guard !password.isEmpty else {
            throw OpaqueError.invalidInput("Password cannot be empty")
        }
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else { throw OpaqueError.invalidState }

        var request = Data(count: Constants.registrationRequestLength)

        let result = try state.withHandle { stateHandle in
            password.withUnsafeBytes { passwordPtr in
                request.withUnsafeMutableBytes { requestPtr in
                    opaque_agent_create_registration_request(
                        handle,
                        passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        password.count,
                        stateHandle,
                        requestPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.registrationRequestLength
                    )
                }
            }
        }

        guard result.rawValue == 0 else { throw OpaqueError.fromCode(result) }
        return request
    }

    /// **Registration step 2/2.** Finalizes registration and returns a 169-byte record.
    ///
    /// - Throws: ``OpaqueError/authenticationError`` if server public key doesn't match (MITM).
    public func finalizeRegistration(response: Data, state: AgentState) throws -> Data {
        guard response.count == Constants.registrationResponseLength else {
            throw OpaqueError.invalidInput(
                "Response must be \(Constants.registrationResponseLength) bytes"
            )
        }
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else { throw OpaqueError.invalidState }

        var record = Data(count: Constants.registrationRecordLength)

        let result = try state.withHandle { stateHandle in
            response.withUnsafeBytes { responsePtr in
                record.withUnsafeMutableBytes { recordPtr in
                    opaque_agent_finalize_registration(
                        handle,
                        responsePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        response.count,
                        stateHandle,
                        recordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.registrationRecordLength
                    )
                }
            }
        }

        guard result.rawValue == 0 else { throw OpaqueError.fromCode(result) }
        return record
    }

    // ── Authentication ────────────────────────────────────────────────────────

    /// **Authentication step 1/3.** Produces a 1273-byte KE1 message.
    public func generateKE1(password: Data, accountId: Data, state: AgentState) throws -> Data {
        guard !password.isEmpty else {
            throw OpaqueError.invalidInput("Password cannot be empty")
        }
        guard !accountId.isEmpty else {
            throw OpaqueError.invalidInput("Account identifier cannot be empty")
        }
        guard accountId.count <= Constants.maxAccountIdLength else {
            throw OpaqueError.invalidInput(
                "Account identifier must be at most \(Constants.maxAccountIdLength) bytes"
            )
        }
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else { throw OpaqueError.invalidState }

        var ke1 = Data(count: Constants.ke1Length)

        let result = try state.withHandle { stateHandle in
            password.withUnsafeBytes { passwordPtr in
                accountId.withUnsafeBytes { accountIdPtr in
                    ke1.withUnsafeMutableBytes { ke1Ptr in
                        opaque_agent_generate_ke1(
                            handle,
                            passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            password.count,
                            accountIdPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            accountId.count,
                            stateHandle,
                            ke1Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            Constants.ke1Length
                        )
                    }
                }
            }
        }

        guard result.rawValue == 0 else { throw OpaqueError.fromCode(result) }
        return ke1
    }

    /// **Authentication step 2/3.** Processes KE2 and produces a 65-byte KE3.
    ///
    /// - Throws: ``OpaqueError/authenticationError`` on wrong password or tampered KE2.
    public func generateKE3(ke2: Data, state: AgentState) throws -> Data {
        guard ke2.count == Constants.ke2Length else {
            throw OpaqueError.invalidInput("KE2 must be \(Constants.ke2Length) bytes")
        }
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else { throw OpaqueError.invalidState }

        var ke3 = Data(count: Constants.ke3Length)

        let result = try state.withHandle { stateHandle in
            ke2.withUnsafeBytes { ke2Ptr in
                ke3.withUnsafeMutableBytes { ke3Ptr in
                    opaque_agent_generate_ke3(
                        handle,
                        ke2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ke2.count,
                        stateHandle,
                        ke3Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.ke3Length
                    )
                }
            }
        }

        guard result.rawValue == 0 else { throw OpaqueError.fromCode(result) }
        return ke3
    }

    /// **Authentication step 3/3.** Extracts shared session (64 bytes) and master (32 bytes) keys.
    ///
    /// Keys are memory-locked and must be explicitly disposed after use.
    public func finish(state: AgentState) throws -> AuthenticationKeys {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else { throw OpaqueError.invalidState }

        var sessionKey = Data(count: Constants.sessionKeyLength)
        var masterKey  = Data(count: Constants.masterKeyLength)
        defer {
            secureZeroData(&sessionKey)
            secureZeroData(&masterKey)
        }

        let result = try state.withHandle { stateHandle in
            sessionKey.withUnsafeMutableBytes { sessionPtr in
                masterKey.withUnsafeMutableBytes { masterPtr in
                    opaque_agent_finish(
                        handle,
                        stateHandle,
                        sessionPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.sessionKeyLength,
                        masterPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.masterKeyLength
                    )
                }
            }
        }

        guard result.rawValue == 0 else { throw OpaqueError.fromCode(result) }
        return AuthenticationKeys(sessionKey: sessionKey, masterKey: masterKey)
    }
}

// ── AgentState ────────────────────────────────────────────────────────────────

extension OpaqueAgent {
    /// Ephemeral state for a single registration or authentication session.
    ///
    /// Create via ``OpaqueAgent/createState()``. Expires after 5 minutes.
    /// Call ``dispose()`` when done to securely zeroize all key material.
    public final class AgentState: @unchecked Sendable {
        private var handle: OpaquePointer?
        private let lock = NSLock()

        internal init() throws {
            var rawHandle: OpaquePointer?
            let result = opaque_agent_state_create(&rawHandle)

            guard result.rawValue == 0, let h = rawHandle else {
                throw OpaqueError.fromCode(result)
            }
            self.handle = h
        }

        internal func withHandle<T>(_ body: (OpaquePointer?) throws -> T) throws -> T {
            lock.lock()
            defer { lock.unlock() }
            guard let h = handle else { throw OpaqueError.invalidState }
            return try body(h)
        }

        /// Releases the native state and securely zeroizes its memory.
        /// Safe to call multiple times. Also called automatically on `deinit`.
        public func dispose() {
            lock.lock()
            var h: OpaquePointer? = handle
            handle = nil
            lock.unlock()
            if h != nil {
                opaque_agent_state_destroy(&h)
            }
        }

        deinit { dispose() }
    }
}

// ── AuthenticationKeys ────────────────────────────────────────────────────────

/// Shared cryptographic keys produced after a successful authentication.
///
/// Keys are memory-locked (`mlock`) to prevent swapping to disk.
/// Access them through ``withSessionKey(_:)`` and ``withMasterKey(_:)``,
/// then call ``dispose()`` to securely zeroize and unlock the memory.
public final class AuthenticationKeys: @unchecked Sendable {
    private var _sessionKey: Data
    private var _masterKey:  Data
    private let lock    = NSLock()
    private var disposed = false

    internal init(sessionKey: Data, masterKey: Data) {
        self._sessionKey = sessionKey
        self._masterKey  = masterKey
        _sessionKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            _ = mlock(base, bytes.count)
        }
        _masterKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            _ = mlock(base, bytes.count)
        }
    }

    /// Accesses the 64-byte session key within a scoped closure.
    /// - Throws: ``OpaqueError/invalidState`` if already disposed.
    public func withSessionKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_sessionKey)
    }

    /// Accesses the 32-byte master key within a scoped closure.
    /// - Throws: ``OpaqueError/invalidState`` if already disposed.
    public func withMasterKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_masterKey)
    }

    /// Securely zeroizes both keys and unlocks the memory pages.
    /// Safe to call multiple times. Also called automatically on `deinit`.
    public func dispose() {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { return }
        disposed = true
        _sessionKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            secureZeroBytes(base.assumingMemoryBound(to: UInt8.self), bytes.count)
            munlock(base, bytes.count)
        }
        _masterKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            secureZeroBytes(base.assumingMemoryBound(to: UInt8.self), bytes.count)
            munlock(base, bytes.count)
        }
        _sessionKey = Data()
        _masterKey  = Data()
    }

    deinit { dispose() }
}

// ── Constants ─────────────────────────────────────────────────────────────────

extension OpaqueAgent {
    /// Wire sizes and cryptographic constants used by the protocol.
    public enum Constants {
        public static let publicKeyLength              = 32
        public static let privateKeyLength             = 32
        public static let registrationRequestLength    = 33
        public static let registrationResponseLength   = 65
        public static let registrationRecordLength     = 169
        public static let sessionKeyLength             = 64
        public static let masterKeyLength              = 32
        public static let ke1Length                    = 1273
        public static let ke2Length                    = 1377
        public static let ke3Length                    = 65
        public static let kemPublicKeyLength           = 1184
        public static let kemCiphertextLength          = 1088
        public static let maxAccountIdLength           = 1024
    }
}
