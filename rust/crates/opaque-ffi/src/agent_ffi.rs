// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Agent (Client) FFI — for Swift / mobile integration
//!
//! This module provides the client-side OPAQUE API. A typical iOS/macOS app
//! imports the generated C header and calls these functions through Swift's
//! C interop.
//!
//! ## Lifecycle overview
//!
//! ```text
//! ┌─────────────────────── SETUP ───────────────────────┐
//! │ opaque_init()                                       │
//! │ opaque_agent_create(relay_pk, 32, &handle)          │
//! │ opaque_agent_state_create(&state)                   │
//! └─────────────────────────────────────────────────────┘
//!
//! ┌─────────────── REGISTRATION (one-time) ─────────────┐
//! │ opaque_agent_create_registration_request(            │
//! │     handle, password, password_len,                  │
//! │     state, &request[33], 33)                         │
//! │                                                      │
//! │         ──── send request[33] to server ────►        │
//! │         ◄─── receive response[65] ──────────         │
//! │                                                      │
//! │ opaque_agent_finalize_registration(                   │
//! │     handle, response, 65, state, &record[169], 169)  │
//! │                                                      │
//! │         ──── send record[169] to server ────►        │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌─────────────── AUTHENTICATION (each login) ─────────┐
//! │ opaque_agent_state_create(&state)   // fresh state   │
//! │                                                      │
//! │ opaque_agent_generate_ke1(                           │
//! │     handle, password, password_len,                  │
//! │     state, &ke1[1273], 1273)                         │
//! │                                                      │
//! │         ──── send ke1[1273] to server ────►          │
//! │         ◄─── receive ke2[1377] ──────────            │
//! │                                                      │
//! │ opaque_agent_generate_ke3(                           │
//! │     handle, ke2, 1377, state, &ke3[65], 65)          │
//! │                                                      │
//! │         ──── send ke3[65] to server ────►            │
//! │                                                      │
//! │ opaque_agent_finish(                                 │
//! │     handle, state,                                   │
//! │     &session_key[64], 64,                            │
//! │     &master_key[32], 32)                             │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌─────────────────── CLEANUP ─────────────────────────┐
//! │ opaque_agent_state_destroy(&state)                   │
//! │ opaque_agent_destroy(&handle)                        │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Swift usage example
//!
//! ```swift
//! // Setup
//! opaque_init()
//!
//! var agentHandle: UnsafeMutableRawPointer?
//! let relayPk: [UInt8] = ... // 32 bytes from server
//! opaque_agent_create(relayPk, relayPk.count, &agentHandle)
//!
//! var stateHandle: UnsafeMutableRawPointer?
//! opaque_agent_state_create(&stateHandle)
//!
//! // Authentication
//! let password = Array("hunter2".utf8)
//! var ke1 = [UInt8](repeating: 0, count: Int(opaque_get_ke1_length()))
//! opaque_agent_generate_ke1(agentHandle, password, password.count,
//!                           stateHandle, &ke1, ke1.count)
//!
//! // ... send ke1 to server, receive ke2 ...
//!
//! var ke3 = [UInt8](repeating: 0, count: Int(opaque_get_ke3_length()))
//! opaque_agent_generate_ke3(agentHandle, ke2, ke2.count,
//!                           stateHandle, &ke3, ke3.count)
//!
//! // ... send ke3 to server ...
//!
//! var sessionKey = [UInt8](repeating: 0, count: 64)
//! var masterKey  = [UInt8](repeating: 0, count: 32)
//! opaque_agent_finish(agentHandle, stateHandle,
//!                     &sessionKey, 64, &masterKey, 32)
//!
//! // Cleanup
//! opaque_agent_state_destroy(&stateHandle)
//! opaque_agent_destroy(&agentHandle)
//! ```

use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3,
    initiator_finish, InitiatorPhase, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator,
    RegistrationRecord, RegistrationRequest,
};
use opaque_core::protocol;
use opaque_core::types::{
    pq, OpaqueError, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH, MASTER_KEY_LENGTH,
    MAX_SECURE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
    REGISTRATION_REQUEST_WIRE_LENGTH, REGISTRATION_RESPONSE_WIRE_LENGTH,
};

use crate::{ffi_error_to_int, result_to_int};

const FFI_PANIC: i32 = -99;

const FFI_BUSY: i32 = -100;

const MAX_ACCOUNT_ID_LENGTH: usize = 1024;

struct AgentHandle {
    initiator: OpaqueInitiator,
    in_use: AtomicBool,
}

impl Drop for AgentHandle {
    fn drop(&mut self) {
        self.initiator.zeroize();
    }
}

struct AgentStateHandle {
    state: InitiatorState,
    ke3_exported: bool,
    in_use: AtomicBool,
}

impl Drop for AgentStateHandle {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn acquire_agent(
    handle: *mut std::ffi::c_void,
) -> Option<(&'static AgentHandle, BusyGuard<'static>)> {
    if handle.is_null() {
        return None;
    }
    let ptr = handle as *const AgentHandle;
    let in_use = unsafe { &(*ptr).in_use };
    if in_use.swap(true, Ordering::Acquire) {
        return None;
    }
    let guard = BusyGuard(in_use);
    Some((unsafe { &*ptr }, guard))
}

fn acquire_agent_state(
    handle: *mut std::ffi::c_void,
) -> Option<(&'static mut AgentStateHandle, BusyGuard<'static>)> {
    if handle.is_null() {
        return None;
    }
    let ptr = handle as *mut AgentStateHandle;
    let in_use = unsafe { &*std::ptr::addr_of!((*ptr).in_use) };
    if in_use.swap(true, Ordering::Acquire) {
        return None;
    }
    let guard = BusyGuard(in_use);
    Some((unsafe { &mut *ptr }, guard))
}

fn invalidate_agent_state(state_handle: &mut AgentStateHandle) {
    state_handle.state.zeroize();
    state_handle.state.phase = InitiatorPhase::Finished;
    state_handle.ke3_exported = false;
}

/// Initializes the OPAQUE library. Must be called once before any other function.
///
/// Returns `0` on success.
#[no_mangle]
pub extern "C" fn opaque_init() -> i32 {
    0
}

/// Creates a new agent (client) handle bound to a specific relay's public key.
///
/// The relay public key is a 32-byte Ristretto255 compressed point obtained from
/// the server during initial setup (e.g., pinned in the app or fetched over TLS).
///
/// # Parameters
///
/// | Name             | Type            | Size    | Description                              |
/// |------------------|-----------------|---------|------------------------------------------|
/// | `relay_public_key` | `*const u8`   | 32      | Relay's static Ristretto255 public key   |
/// | `key_length`     | `usize`         | —       | Must be exactly 32                       |
/// | `handle`         | `*mut *mut void`| —       | Receives the new agent handle (out-param)|
///
/// # Returns
///
/// `0` on success, `-1` if inputs are invalid, `-5` if the provided key material is rejected.
///
/// # Ownership
///
/// The caller owns the returned handle and must free it with [`opaque_agent_destroy`].
///
/// # Safety
///
/// - `relay_public_key` must point to at least `PUBLIC_KEY_LENGTH` (32) readable bytes
///   containing the relay's static public key.
/// - `handle` must be a valid, non-null pointer to a `*mut c_void` that will receive the new
///   agent handle. The caller owns the returned handle and must free it with
///   `opaque_agent_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create(
    relay_public_key: *const u8,
    key_length: usize,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if relay_public_key.is_null() || key_length != PUBLIC_KEY_LENGTH || handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let key = std::slice::from_raw_parts(relay_public_key, key_length);
        let initiator = match OpaqueInitiator::new(key) {
            Ok(i) => i,
            Err(e) => return ffi_error_to_int(e),
        };
        let boxed = Box::new(AgentHandle {
            initiator,
            in_use: AtomicBool::new(false),
        });
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Destroys an agent handle, securely zeroizing all key material.
///
/// After this call, `*handle_ptr` is set to null. Calling destroy on an already-null
/// pointer is a safe no-op.
///
/// # Safety
///
/// `handle_ptr` must be a valid, non-null pointer to a `*mut c_void` that was
/// previously set by `opaque_agent_create`. After this call the inner pointer
/// is set to null, preventing double-free.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_destroy(handle_ptr: *mut *mut std::ffi::c_void) {
    let _ = opaque_agent_try_destroy(handle_ptr);
}

/// Tries to destroy an agent handle and reports the outcome.
///
/// Returns:
/// - `0` on success or if handle is already null.
/// - `-1` if `handle_ptr` is null.
/// - `-100` if the handle is currently in use by another call.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_try_destroy(handle_ptr: *mut *mut std::ffi::c_void) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle_ptr.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let handle = *handle_ptr;
        if handle.is_null() {
            return 0;
        }
        let in_use = &(*(handle as *const AgentHandle)).in_use;
        if in_use.swap(true, Ordering::Acquire) {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        drop(Box::from_raw(handle as *mut AgentHandle));
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Allocates a fresh agent state for one registration or authentication session.
///
/// Each protocol flow (registration or login) requires its own state. The state has a
/// **5-minute lifetime** — if the protocol is not completed within that window, subsequent
/// calls will return `-4` (validation error).
///
/// # Parameters
///
/// | Name     | Type            | Description                             |
/// |----------|-----------------|---------------------------------------- |
/// | `handle` | `*mut *mut void`| Receives the new state handle (out-param)|
///
/// # Returns
///
/// `0` on success. The caller must free the state with [`opaque_agent_state_destroy`].
///
/// # Safety
///
/// `handle` must be a valid, non-null pointer to a `*mut c_void` that will receive the newly
/// allocated state. The caller owns the returned handle and must free it with
/// `opaque_agent_state_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_create(handle: *mut *mut std::ffi::c_void) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let boxed = Box::new(AgentStateHandle {
            state: InitiatorState::new(),
            ke3_exported: false,
            in_use: AtomicBool::new(false),
        });
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Destroys an agent state handle, securely zeroizing all cryptographic material
/// (password, keys, nonces, shared secrets).
///
/// # Safety
///
/// `handle_ptr` must be a valid, non-null pointer to a `*mut c_void` that was
/// previously set by `opaque_agent_state_create`. After this call the inner
/// pointer is set to null, preventing double-free.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_destroy(handle_ptr: *mut *mut std::ffi::c_void) {
    let _ = opaque_agent_state_try_destroy(handle_ptr);
}

/// Tries to destroy an agent state handle and reports the outcome.
///
/// Returns:
/// - `0` on success or if handle is already null.
/// - `-1` if `handle_ptr` is null.
/// - `-100` if the handle is currently in use by another call.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_try_destroy(
    handle_ptr: *mut *mut std::ffi::c_void,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle_ptr.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let handle = *handle_ptr;
        if handle.is_null() {
            return 0;
        }
        let in_use = &(*(handle as *const AgentStateHandle)).in_use;
        if in_use.swap(true, Ordering::Acquire) {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        drop(Box::from_raw(handle as *mut AgentStateHandle));
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Registration step 1/2.** Creates an OPRF-blinded registration request from the
/// user's password.
///
/// The output `request_out` (33 bytes) must be sent to the server, which will respond
/// with a 65-byte registration response.
///
/// # Parameters
///
/// | Name               | Type          | Size        | Description                          |
/// |--------------------|---------------|-------------|--------------------------------------|
/// | `agent_handle`     | `*mut void`   | —           | Agent handle from `opaque_agent_create` |
/// | `secure_key`       | `*const u8`   | 1–4096      | User's password (raw bytes)          |
/// | `secure_key_length`| `usize`       | —           | Length of password in bytes           |
/// | `state_handle`     | `*mut void`   | —           | Fresh state from `opaque_agent_state_create` |
/// | `request_out`      | `*mut u8`     | ≥ 33        | Output buffer for the blinded request|
/// | `request_length`   | `usize`       | —           | Size of output buffer (must be ≥ 33) |
///
/// # Returns
///
/// `0` on success. The 33-byte request is written to `request_out`.
///
/// # Safety
///
/// - `agent_handle` must be a valid pointer to an `AgentHandle` from `opaque_agent_create`.
/// - `secure_key` must point to at least `secure_key_length` readable bytes (the user's
///   password; non-zero length, max `MAX_SECURE_KEY_LENGTH`).
/// - `state_handle` must be a valid pointer to an `AgentStateHandle` from
///   `opaque_agent_state_create`.
/// - `request_out` must point to a writable buffer of at least
///   `REGISTRATION_REQUEST_WIRE_LENGTH` (33) bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create_registration_request(
    agent_handle: *mut std::ffi::c_void,
    secure_key: *const u8,
    secure_key_length: usize,
    state_handle: *mut std::ffi::c_void,
    request_out: *mut u8,
    request_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let secure_key_length = match secure_key_length {
            1..=MAX_SECURE_KEY_LENGTH => secure_key_length,
            _ => return OpaqueError::InvalidInput.to_c_int(),
        };
        if agent_handle.is_null()
            || secure_key.is_null()
            || request_out.is_null()
            || request_length < REGISTRATION_REQUEST_WIRE_LENGTH
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            return FFI_BUSY;
        };

        let key = std::slice::from_raw_parts(secure_key, secure_key_length);
        let mut request = RegistrationRequest::new();

        let result = create_registration_request(key, &mut request, &mut sh.state);
        if result.is_ok() {
            let out = std::slice::from_raw_parts_mut(request_out, request_length);
            if let Err(e) = protocol::write_registration_request(&request.data, out) {
                invalidate_agent_state(sh);
                return ffi_error_to_int(e);
            }
        }
        result_to_int(result)
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Registration step 2/2.** Finalizes registration by creating an encrypted envelope
/// (the registration record).
///
/// Takes the server's 65-byte registration response and produces a 169-byte registration
/// record. The record must be sent to the server for storage — it contains the encrypted
/// envelope and the client's static public key. The server cannot decrypt the envelope.
///
/// # Parameters
///
/// | Name              | Type          | Size   | Description                              |
/// |-------------------|---------------|--------|------------------------------------------|
/// | `agent_handle`    | `*mut void`   | —      | Agent handle from `opaque_agent_create`  |
/// | `response`        | `*const u8`   | 65     | Server's registration response           |
/// | `response_length` | `usize`       | —      | Must be exactly 65                       |
/// | `state_handle`    | `*mut void`   | —      | Same state used in step 1                |
/// | `record_out`      | `*mut u8`     | ≥ 169  | Output buffer for the registration record|
/// | `record_length`   | `usize`       | —      | Size of output buffer (must be ≥ 169)    |
///
/// # Returns
///
/// `0` on success. The 169-byte record is written to `record_out`.
/// Returns `-5` if the server's public key in the response does not match the one
/// provided at agent creation (MITM protection).
///
/// # Safety
///
/// - `agent_handle` must be a valid pointer to an `AgentHandle` from `opaque_agent_create`.
/// - `response` must point to at least `REGISTRATION_RESPONSE_WIRE_LENGTH` (65) readable bytes.
/// - `state_handle` must be a valid pointer to an `AgentStateHandle` used in the prior
///   `opaque_agent_create_registration_request` call.
/// - `record_out` must point to a writable buffer of at least
///   `REGISTRATION_RECORD_LENGTH` bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finalize_registration(
    agent_handle: *mut std::ffi::c_void,
    response: *const u8,
    response_length: usize,
    state_handle: *mut std::ffi::c_void,
    record_out: *mut u8,
    record_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if response.is_null()
            || response_length != REGISTRATION_RESPONSE_WIRE_LENGTH
            || record_out.is_null()
            || record_length < REGISTRATION_RECORD_LENGTH
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let Some((ah, _ag)) = acquire_agent(agent_handle) else {
            return FFI_BUSY;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            return FFI_BUSY;
        };

        let resp = std::slice::from_raw_parts(response, response_length);
        let mut record = RegistrationRecord::new();

        let result = match finalize_registration(&ah.initiator, resp, &mut sh.state, &mut record) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(record_out, record_length);
                let write_result = protocol::write_registration_record(
                    &record.envelope,
                    &record.initiator_public_key,
                    out,
                );
                if write_result.is_err() {
                    invalidate_agent_state(sh);
                }
                write_result
            }
            Err(e) => Err(e),
        };
        result_to_int(result)
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 1/3.** Generates the first key-exchange message (KE1).
///
/// Produces a 1273-byte KE1 message containing:
/// - Protocol version prefix (1 byte)
/// - OPRF-blinded credential request (32 bytes)
/// - Ephemeral Ristretto255 public key (32 bytes)
/// - Random nonce (24 bytes)
/// - Ephemeral ML-KEM-768 public key (1184 bytes)
///
/// The KE1 must be sent to the server along with the user's account identifier.
///
/// # Parameters
///
/// | Name               | Type          | Size        | Description                          |
/// |--------------------|---------------|-------------|--------------------------------------|
/// | `agent_handle`     | `*mut void`   | —           | Agent handle from `opaque_agent_create` |
/// | `secure_key`       | `*const u8`   | 1–4096      | User's password (raw bytes)          |
/// | `secure_key_length`| `usize`       | —           | Length of password in bytes           |
/// | `account_id`       | `*const u8`   | ≥ 1         | Account identifier bound to transcript |
/// | `account_id_length`| `usize`       | —           | Length of account identifier in bytes |
/// | `state_handle`     | `*mut void`   | —           | Fresh state from `opaque_agent_state_create` |
/// | `ke1_out`          | `*mut u8`     | ≥ 1273      | Output buffer for KE1 message        |
/// | `ke1_length`       | `usize`       | —           | Size of output buffer (must be ≥ 1273)|
///
/// # Returns
///
/// `0` on success. The 1273-byte KE1 is written to `ke1_out`.
///
/// # Safety
///
/// - `secure_key` must point to at least `secure_key_length` readable bytes (the user's
///   password; non-zero length, max `MAX_SECURE_KEY_LENGTH`).
/// - `account_id` must point to at least `account_id_length` readable bytes (non-zero).
/// - `state_handle` must be a valid pointer to an `AgentStateHandle` from
///   `opaque_agent_state_create`.
/// - `ke1_out` must point to a writable buffer of at least `KE1_LENGTH` bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke1(
    agent_handle: *mut std::ffi::c_void,
    secure_key: *const u8,
    secure_key_length: usize,
    account_id: *const u8,
    account_id_length: usize,
    state_handle: *mut std::ffi::c_void,
    ke1_out: *mut u8,
    ke1_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        let secure_key_length = match secure_key_length {
            1..=MAX_SECURE_KEY_LENGTH => secure_key_length,
            _ => return OpaqueError::InvalidInput.to_c_int(),
        };
        if agent_handle.is_null()
            || secure_key.is_null()
            || account_id.is_null()
            || account_id_length == 0
            || account_id_length > MAX_ACCOUNT_ID_LENGTH
            || ke1_out.is_null()
            || ke1_length < KE1_LENGTH
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            return FFI_BUSY;
        };

        let key = std::slice::from_raw_parts(secure_key, secure_key_length);
        let account_id = std::slice::from_raw_parts(account_id, account_id_length);
        let mut ke1 = Ke1Message::new();

        let result = match generate_ke1(key, account_id, &mut ke1, &mut sh.state) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(ke1_out, ke1_length);
                let write_result = protocol::write_ke1(
                    &ke1.credential_request,
                    &ke1.initiator_public_key,
                    &ke1.initiator_nonce,
                    &ke1.pq_ephemeral_public_key,
                    out,
                );
                if write_result.is_err() {
                    invalidate_agent_state(sh);
                }
                write_result
            }
            Err(e) => Err(e),
        };
        result_to_int(result)
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 2/3.** Processes the server's KE2 and produces KE3.
///
/// This is the core authentication step. It:
/// 1. Unblinds the OPRF output and derives the randomized password via Argon2id
/// 2. Decrypts the envelope to recover the client's static keys
/// 3. Performs 4-way Diffie-Hellman (3DH + ephemeral-ephemeral)
/// 4. Decapsulates the ML-KEM-768 ciphertext
/// 5. Combines classical and post-quantum key material (AND-model)
/// 6. Verifies the server's MAC (mutual authentication)
/// 7. Computes the client's MAC for the server to verify
///
/// If the password is wrong, envelope decryption fails and returns `-5`.
///
/// # Parameters
///
/// | Name           | Type          | Size   | Description                           |
/// |----------------|---------------|--------|---------------------------------------|
/// | `agent_handle` | `*mut void`   | —      | Agent handle from `opaque_agent_create`|
/// | `ke2`          | `*const u8`   | 1377   | Server's KE2 message                 |
/// | `ke2_length`   | `usize`       | —      | Must be exactly 1377                  |
/// | `state_handle` | `*mut void`   | —      | Same state used in `generate_ke1`     |
/// | `ke3_out`      | `*mut u8`     | ≥ 65   | Output buffer for KE3 message         |
/// | `ke3_length`   | `usize`       | —      | Size of output buffer (must be ≥ 65)  |
///
/// # Returns
///
/// `0` on success. The 65-byte KE3 is written to `ke3_out`.
/// Returns `-5` if authentication fails (wrong password or tampered KE2).
///
/// # Safety
///
/// - `agent_handle` must be a valid pointer to an `AgentHandle` from `opaque_agent_create`.
/// - `ke2` must point to at least `KE2_LENGTH` readable bytes.
/// - `state_handle` must be a valid pointer to an `AgentStateHandle` used in the prior
///   `opaque_agent_generate_ke1` call.
/// - `ke3_out` must point to a writable buffer of at least `KE3_LENGTH` bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke3(
    agent_handle: *mut std::ffi::c_void,
    ke2: *const u8,
    ke2_length: usize,
    state_handle: *mut std::ffi::c_void,
    ke3_out: *mut u8,
    ke3_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if ke2.is_null() || ke2_length != KE2_LENGTH || ke3_out.is_null() || ke3_length < KE3_LENGTH
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let Some((ah, _ag)) = acquire_agent(agent_handle) else {
            return FFI_BUSY;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            return FFI_BUSY;
        };

        let ke2 = std::slice::from_raw_parts(ke2, ke2_length);
        let mut ke3 = Ke3Message::new();
        sh.ke3_exported = false;

        let result = match generate_ke3(&ah.initiator, ke2, &mut sh.state, &mut ke3) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(ke3_out, ke3_length);
                let write_result = protocol::write_ke3(&ke3.initiator_mac, out);
                if write_result.is_ok() {
                    sh.ke3_exported = true;
                } else {
                    invalidate_agent_state(sh);
                }
                write_result
            }
            Err(e) => Err(e),
        };
        result_to_int(result)
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 3/3.** Extracts the session key and master key after a
/// successful handshake.
///
/// Call this after `opaque_agent_generate_ke3` succeeds. The session key (64 bytes) and
/// master key (32 bytes) are identical on both client and server, and can be used
/// for subsequent symmetric encryption (e.g., AES-GCM, ChaCha20-Poly1305).
///
/// After this call, all sensitive state is securely zeroized.
///
/// # Parameters
///
/// | Name               | Type        | Size  | Description                              |
/// |--------------------|-------------|-------|------------------------------------------|
/// | `_agent_handle`    | `*mut void` | —     | Reserved (pass the agent handle)         |
/// | `state_handle`     | `*mut void` | —     | Same state used in `generate_ke3`        |
/// | `session_key_out`  | `*mut u8`   | ≥ 64  | Output buffer for the 64-byte session key|
/// | `session_key_length`| `usize`    | —     | Size of session key buffer (must be ≥ 64)|
/// | `master_key_out`   | `*mut u8`   | ≥ 32  | Output buffer for the 32-byte master key |
/// | `master_key_length`| `usize`     | —     | Size of master key buffer (must be ≥ 32) |
///
/// # Returns
///
/// `0` on success. Both keys are written to their respective buffers.
/// Returns `-5` if KE3 has not been successfully exported by
/// `opaque_agent_generate_ke3`.
///
/// # Safety
///
/// - `state_handle` must be a valid pointer to an `AgentStateHandle` used in the prior
///   `opaque_agent_generate_ke3` call.
/// - `session_key_out` must point to a writable buffer of at least `HASH_LENGTH` (64) bytes.
/// - `master_key_out` must point to a writable buffer of at least `MASTER_KEY_LENGTH` (32)
///   bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finish(
    _agent_handle: *mut std::ffi::c_void,
    state_handle: *mut std::ffi::c_void,
    session_key_out: *mut u8,
    session_key_length: usize,
    master_key_out: *mut u8,
    master_key_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if session_key_out.is_null()
            || session_key_length < HASH_LENGTH
            || master_key_out.is_null()
            || master_key_length < MASTER_KEY_LENGTH
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            return FFI_BUSY;
        };
        if !sh.ke3_exported {
            return ffi_error_to_int(OpaqueError::ValidationError);
        }

        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; MASTER_KEY_LENGTH];

        let rc = match initiator_finish(&mut sh.state, &mut session_key, &mut master_key) {
            Ok(()) => {
                ptr::copy_nonoverlapping(session_key.as_ptr(), session_key_out, HASH_LENGTH);
                ptr::copy_nonoverlapping(master_key.as_ptr(), master_key_out, MASTER_KEY_LENGTH);
                0
            }
            Err(e) => ffi_error_to_int(e),
        };
        session_key.zeroize();
        master_key.zeroize();
        sh.ke3_exported = false;
        rc
    }))
    .unwrap_or(FFI_PANIC)
}

/// Returns `KE1_LENGTH` (1273). Use to allocate the KE1 output buffer.
#[no_mangle]
pub extern "C" fn opaque_get_ke1_length() -> usize {
    KE1_LENGTH
}

/// Returns `KE2_LENGTH` (1377). Use to validate incoming KE2 messages.
#[no_mangle]
pub extern "C" fn opaque_get_ke2_length() -> usize {
    KE2_LENGTH
}

/// Returns `KE3_LENGTH` (65). Use to allocate the KE3 output buffer.
#[no_mangle]
pub extern "C" fn opaque_get_ke3_length() -> usize {
    KE3_LENGTH
}

/// Returns `REGISTRATION_RECORD_LENGTH` (169). Use to allocate the record output buffer.
#[no_mangle]
pub extern "C" fn opaque_get_registration_record_length() -> usize {
    REGISTRATION_RECORD_LENGTH
}

/// Returns `REGISTRATION_REQUEST_WIRE_LENGTH` (33). Use to allocate the registration request buffer.
#[no_mangle]
pub extern "C" fn opaque_get_registration_request_length() -> usize {
    REGISTRATION_REQUEST_WIRE_LENGTH
}

/// Returns `REGISTRATION_RESPONSE_WIRE_LENGTH` (65). Expected size of incoming registration responses.
#[no_mangle]
pub extern "C" fn opaque_get_registration_response_length() -> usize {
    REGISTRATION_RESPONSE_WIRE_LENGTH
}

/// Returns `KEM_PUBLIC_KEY_LENGTH` (1184). ML-KEM-768 public key size.
#[no_mangle]
pub extern "C" fn opaque_get_kem_public_key_length() -> usize {
    pq::KEM_PUBLIC_KEY_LENGTH
}

/// Returns `KEM_CIPHERTEXT_LENGTH` (1088). ML-KEM-768 ciphertext size.
#[no_mangle]
pub extern "C" fn opaque_get_kem_ciphertext_length() -> usize {
    pq::KEM_CIPHERTEXT_LENGTH
}
