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
//! │     handle, response, 65, state, &record[201], 201)  │
//! │                                                      │
//! │         ──── send record[201] to server ────►        │
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
//! │     &export_key[32], 32)                             │
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
//! var exportKey  = [UInt8](repeating: 0, count: 32)
//! opaque_agent_finish(agentHandle, stateHandle,
//!                     &sessionKey, 64, &exportKey, 32)
//!
//! // Cleanup
//! opaque_agent_state_destroy(&stateHandle)
//! opaque_agent_destroy(&agentHandle)
//! ```

use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize, Zeroizing};

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3,
    initiator_finish, InitiatorPhase, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator,
    RegistrationRecord, RegistrationRequest,
};
use opaque_core::protocol;
use opaque_core::types::{
    pq, OpaqueError, EXPORT_KEY_LENGTH, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH,
    MAX_SECURE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
    REGISTRATION_REQUEST_WIRE_LENGTH, REGISTRATION_RESPONSE_WIRE_LENGTH,
};

use crate::{
    ffi_error_to_int, handle_access_to_int, inject_test_panic, ranges_overlap, HandleAccessError,
};

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
        #[cfg(test)]
        crate::record_disposal_observation(
            "AgentStateHandle",
            vec![
                (
                    "initiator_private_key",
                    opaque_core::types::is_all_zero(self.state.initiator_private_key()),
                ),
                (
                    "initiator_ephemeral_private_key",
                    opaque_core::types::is_all_zero(self.state.initiator_ephemeral_private_key()),
                ),
                (
                    "pq_ephemeral_secret_key",
                    opaque_core::types::is_all_zero(self.state.pq_ephemeral_secret_key()),
                ),
                (
                    "pq_shared_secret",
                    opaque_core::types::is_all_zero(self.state.pq_shared_secret()),
                ),
            ],
        );
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
) -> Result<(&'static AgentHandle, BusyGuard<'static>), HandleAccessError> {
    if handle.is_null() {
        return Err(HandleAccessError::InvalidHandle);
    }
    let ptr = handle as *const AgentHandle;
    // SAFETY: the public contract requires a live AgentHandle created by this library.
    let in_use = unsafe { &(*ptr).in_use };
    if in_use
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(HandleAccessError::Busy);
    }
    let guard = BusyGuard(in_use);
    // SAFETY: external lifetime synchronization keeps the allocation alive while the guard is held.
    Ok((unsafe { &*ptr }, guard))
}

fn acquire_agent_state(
    handle: *mut std::ffi::c_void,
) -> Result<(&'static mut AgentStateHandle, BusyGuard<'static>), HandleAccessError> {
    if handle.is_null() {
        return Err(HandleAccessError::InvalidHandle);
    }
    let ptr = handle as *mut AgentStateHandle;
    // SAFETY: the public contract requires a live AgentStateHandle created by this library.
    let in_use = unsafe { &*std::ptr::addr_of!((*ptr).in_use) };
    if in_use
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(HandleAccessError::Busy);
    }
    let guard = BusyGuard(in_use);
    // SAFETY: admission is exclusive and external synchronization keeps the allocation alive.
    Ok((unsafe { &mut *ptr }, guard))
}

fn invalidate_agent_state(state_handle: &mut AgentStateHandle) {
    state_handle.state.zeroize();
    state_handle.state.phase = InitiatorPhase::Finished;
    state_handle.ke3_exported = false;
}

fn run_agent_stateful(
    state_handle: &mut AgentStateHandle,
    operation: impl FnOnce(&mut AgentStateHandle) -> opaque_core::types::OpaqueResult<()>,
) -> i32 {
    match panic::catch_unwind(AssertUnwindSafe(|| operation(state_handle))) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            invalidate_agent_state(state_handle);
            ffi_error_to_int(error)
        }
        Err(_) => {
            invalidate_agent_state(state_handle);
            FFI_PANIC
        }
    }
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
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        if relay_public_key.is_null()
            || key_length != PUBLIC_KEY_LENGTH
            || ranges_overlap(
                relay_public_key,
                key_length,
                handle.cast::<u8>(),
                std::mem::size_of::<*mut std::ffi::c_void>(),
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: pointer and exact readable extent are required by the public contract.
        // SAFETY: pointer and exact readable extent are required by the public contract.
        let key = unsafe { std::slice::from_raw_parts(relay_public_key, key_length) };
        let initiator = match OpaqueInitiator::new(key) {
            Ok(i) => i,
            Err(e) => return ffi_error_to_int(e),
        };
        let boxed = Box::new(AgentHandle {
            initiator,
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("agent_create_before_publish");
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
/// is set to null, preventing double-free. The caller must ensure that destruction does not
/// overlap any operation through this handle or a copied alias.
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
        if in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        // SAFETY: external quiescence and canonical-slot ownership are caller obligations.
        drop(unsafe { Box::from_raw(handle as *mut AgentHandle) });
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
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        let boxed = Box::new(AgentStateHandle {
            state: InitiatorState::new(),
            ke3_exported: false,
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("agent_state_create_before_publish");
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
/// pointer is set to null, preventing double-free. The caller must ensure that destruction does
/// not overlap any operation through this state handle or a copied alias.
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
        if in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        // SAFETY: external quiescence and canonical-slot ownership are caller obligations.
        drop(unsafe { Box::from_raw(handle as *mut AgentStateHandle) });
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
        if secure_key.is_null()
            || request_out.is_null()
            || request_length < REGISTRATION_REQUEST_WIRE_LENGTH
            || ranges_overlap(
                secure_key,
                secure_key_length,
                request_out.cast_const(),
                REGISTRATION_REQUEST_WIRE_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (_ah, _ag) = match acquire_agent(agent_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_agent_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_agent_stateful(sh, |sh| {
            // SAFETY: validated readable extent is part of the public ABI contract.
            let key = unsafe { std::slice::from_raw_parts(secure_key, secure_key_length) };
            let mut request = RegistrationRequest::new();
            create_registration_request(key, &mut request, &mut sh.state)?;

            let mut wire = Zeroizing::new([0u8; REGISTRATION_REQUEST_WIRE_LENGTH]);
            protocol::write_registration_request(&request.data, &mut *wire)?;
            inject_test_panic("agent_registration_request_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe {
                ptr::copy_nonoverlapping(
                    wire.as_ptr(),
                    request_out,
                    REGISTRATION_REQUEST_WIRE_LENGTH,
                )
            };
            Ok(())
        })
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Registration step 2/2.** Finalizes registration by creating an encrypted envelope
/// (the registration record).
///
/// Takes the server's 65-byte registration response and produces a 201-byte registration
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
/// | `record_out`      | `*mut u8`     | ≥ 201  | Output buffer for the registration record|
/// | `record_length`   | `usize`       | —      | Size of output buffer (must be ≥ 201)    |
///
/// # Returns
///
/// `0` on success. The 201-byte record is written to `record_out`.
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
            || ranges_overlap(
                response,
                response_length,
                record_out.cast_const(),
                REGISTRATION_RECORD_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (ah, _ag) = match acquire_agent(agent_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_agent_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_agent_stateful(sh, |sh| {
            // SAFETY: validated readable extent is part of the public ABI contract.
            let resp = unsafe { std::slice::from_raw_parts(response, response_length) };
            let mut record = RegistrationRecord::new();
            finalize_registration(&ah.initiator, resp, &mut sh.state, &mut record)?;

            let mut wire = Zeroizing::new([0u8; REGISTRATION_RECORD_LENGTH]);
            protocol::write_registration_record(
                &record.envelope,
                &record.initiator_public_key,
                &mut *wire,
            )?;
            inject_test_panic("agent_finalize_registration_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe {
                ptr::copy_nonoverlapping(wire.as_ptr(), record_out, REGISTRATION_RECORD_LENGTH)
            };
            Ok(())
        })
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
        if secure_key.is_null()
            || account_id.is_null()
            || account_id_length == 0
            || account_id_length > MAX_ACCOUNT_ID_LENGTH
            || ke1_out.is_null()
            || ke1_length < KE1_LENGTH
            || ranges_overlap(
                secure_key,
                secure_key_length,
                ke1_out.cast_const(),
                KE1_LENGTH,
            )
            || ranges_overlap(
                account_id,
                account_id_length,
                ke1_out.cast_const(),
                KE1_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (_ah, _ag) = match acquire_agent(agent_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_agent_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_agent_stateful(sh, |sh| {
            // SAFETY: validated readable extents are part of the public ABI contract.
            let key = unsafe { std::slice::from_raw_parts(secure_key, secure_key_length) };
            let account_id = unsafe { std::slice::from_raw_parts(account_id, account_id_length) };
            let mut ke1 = Ke1Message::new();
            generate_ke1(key, account_id, &mut ke1, &mut sh.state)?;

            let mut wire = Zeroizing::new([0u8; KE1_LENGTH]);
            protocol::write_ke1(
                &ke1.credential_request,
                &ke1.initiator_public_key,
                &ke1.initiator_nonce,
                &ke1.pq_ephemeral_public_key,
                &mut *wire,
            )?;
            inject_test_panic("agent_generate_ke1_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe { ptr::copy_nonoverlapping(wire.as_ptr(), ke1_out, KE1_LENGTH) };
            Ok(())
        })
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
        if ke2.is_null()
            || ke2_length != KE2_LENGTH
            || ke3_out.is_null()
            || ke3_length < KE3_LENGTH
            || ranges_overlap(ke2, ke2_length, ke3_out.cast_const(), KE3_LENGTH)
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (ah, _ag) = match acquire_agent(agent_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_agent_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_agent_stateful(sh, |sh| {
            // SAFETY: validated readable extent is part of the public ABI contract.
            let ke2 = unsafe { std::slice::from_raw_parts(ke2, ke2_length) };
            let mut ke3 = Ke3Message::new();
            sh.ke3_exported = false;
            generate_ke3(&ah.initiator, ke2, &mut sh.state, &mut ke3)?;

            let mut wire = Zeroizing::new([0u8; KE3_LENGTH]);
            protocol::write_ke3(&ke3.initiator_mac, &mut *wire)?;
            inject_test_panic("agent_generate_ke3_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe { ptr::copy_nonoverlapping(wire.as_ptr(), ke3_out, KE3_LENGTH) };
            sh.ke3_exported = true;
            Ok(())
        })
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 3/3.** Extracts the session key and client-only export key after a
/// successful handshake.
///
/// Call this after `opaque_agent_generate_ke3` succeeds. The session key (64 bytes) and
/// export key (32 bytes) is derived from the password-authenticated OPRF result
/// and is never available to the relay. The session key is shared with the relay.
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
/// | `export_key_out`   | `*mut u8`   | ≥ 32  | Output buffer for the 32-byte client export key |
/// | `export_key_length`| `usize`     | —     | Size of export-key buffer (must be ≥ 32) |
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
/// - `export_key_out` must point to a writable buffer of at least `EXPORT_KEY_LENGTH` (32)
///   bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finish(
    agent_handle: *mut std::ffi::c_void,
    state_handle: *mut std::ffi::c_void,
    session_key_out: *mut u8,
    session_key_length: usize,
    export_key_out: *mut u8,
    export_key_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if session_key_out.is_null()
            || session_key_length < HASH_LENGTH
            || export_key_out.is_null()
            || export_key_length < EXPORT_KEY_LENGTH
            || ranges_overlap(
                session_key_out.cast_const(),
                HASH_LENGTH,
                export_key_out.cast_const(),
                EXPORT_KEY_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (_ah, _ag) = match acquire_agent(agent_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_agent_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_agent_stateful(sh, |sh| {
            if !sh.ke3_exported {
                return Err(OpaqueError::ValidationError);
            }

            let mut session_key = Zeroizing::new([0u8; HASH_LENGTH]);
            let mut export_key = Zeroizing::new([0u8; EXPORT_KEY_LENGTH]);
            initiator_finish(&mut sh.state, &mut session_key, &mut export_key)?;
            inject_test_panic("agent_finish_before_commit");
            // SAFETY: both outputs were validated as writable, sufficiently large, and disjoint.
            unsafe {
                ptr::copy_nonoverlapping(session_key.as_ptr(), session_key_out, HASH_LENGTH);
                ptr::copy_nonoverlapping(export_key.as_ptr(), export_key_out, EXPORT_KEY_LENGTH);
            }
            sh.ke3_exported = false;
            Ok(())
        })
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

/// Returns `REGISTRATION_RECORD_LENGTH` (201). Use to allocate the record output buffer.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_ffi::{
        opaque_relay_build_credentials, opaque_relay_create,
        opaque_relay_create_registration_response, opaque_relay_destroy, opaque_relay_generate_ke2,
        opaque_relay_keypair_destroy, opaque_relay_keypair_generate,
        opaque_relay_keypair_get_public_key, opaque_relay_state_create, opaque_relay_state_destroy,
    };
    use crate::{set_ffi_panic_point, take_disposal_observations};
    use opaque_core::types::is_all_zero;
    use opaque_relay::OpaqueResponder;

    const PASSWORD: &[u8] = b"correct horse battery staple";
    const ACCOUNT_ID: &[u8] = b"alice@example.com";

    unsafe fn create_agent_and_state() -> (*mut std::ffi::c_void, *mut std::ffi::c_void) {
        let responder = OpaqueResponder::generate().expect("responder generation");
        let mut agent = ptr::null_mut();
        // SAFETY: test-owned key and output slot satisfy the public contract.
        assert_eq!(
            unsafe {
                opaque_agent_create(
                    responder.public_key().as_ptr(),
                    responder.public_key().len(),
                    &mut agent,
                )
            },
            0
        );
        let mut state = ptr::null_mut();
        // SAFETY: test-owned output slot satisfies the public contract.
        assert_eq!(unsafe { opaque_agent_state_create(&mut state) }, 0);
        (agent, state)
    }

    #[derive(Clone, Copy, Debug)]
    enum AgentStatefulOperation {
        RegistrationRequest,
        FinalizeRegistration,
        GenerateKe1,
        GenerateKe3,
        Finish,
    }

    fn is_legal_agent_cell(phase: InitiatorPhase, operation: AgentStatefulOperation) -> bool {
        matches!(
            (phase, operation),
            (
                InitiatorPhase::Created,
                AgentStatefulOperation::RegistrationRequest | AgentStatefulOperation::GenerateKe1
            ) | (
                InitiatorPhase::RegistrationRequested,
                AgentStatefulOperation::FinalizeRegistration
            ) | (
                InitiatorPhase::Ke1Generated,
                AgentStatefulOperation::GenerateKe3
            ) | (InitiatorPhase::Ke3Generated, AgentStatefulOperation::Finish)
        )
    }

    #[test]
    fn constructor_failure_nulls_non_null_sentinel() {
        let invalid_key = [0u8; PUBLIC_KEY_LENGTH];
        let mut agent = std::ptr::dangling_mut::<std::ffi::c_void>();

        // SAFETY: the input and output allocations are valid; key contents are intentionally bad.
        let rc =
            unsafe { opaque_agent_create(invalid_key.as_ptr(), invalid_key.len(), &mut agent) };

        assert_ne!(rc, 0);
        assert!(agent.is_null());
    }

    #[test]
    fn constructor_panic_leaves_out_slot_null() {
        let responder = OpaqueResponder::generate().expect("responder generation");
        let mut agent = std::ptr::dangling_mut::<std::ffi::c_void>();
        set_ffi_panic_point(Some("agent_create_before_publish"));

        // SAFETY: test-owned key and output slot satisfy the public contract.
        let rc = unsafe {
            opaque_agent_create(
                responder.public_key().as_ptr(),
                responder.public_key().len(),
                &mut agent,
            )
        };

        assert_eq!(rc, FFI_PANIC);
        assert!(agent.is_null());
    }

    #[test]
    fn state_constructor_panic_leaves_out_slot_null() {
        let mut state = std::ptr::dangling_mut::<std::ffi::c_void>();
        set_ffi_panic_point(Some("agent_state_create_before_publish"));

        // SAFETY: the test-owned output slot satisfies the public contract.
        let rc = unsafe { opaque_agent_state_create(&mut state) };

        assert_eq!(rc, FFI_PANIC);
        assert!(state.is_null());
    }

    #[test]
    fn null_and_busy_handles_have_distinct_status_codes() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut output = [0u8; KE1_LENGTH];

        // SAFETY: this unit test owns the live handle and only simulates an admitted peer call.
        unsafe {
            (*(agent as *mut AgentHandle))
                .in_use
                .store(true, Ordering::Release)
        };
        // SAFETY: all byte ranges and the state handle are valid; the agent is deliberately busy.
        let busy_rc = unsafe {
            opaque_agent_generate_ke1(
                agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                state,
                output.as_mut_ptr(),
                output.len(),
            )
        };
        // SAFETY: this unit test owns the handle and restores it before destruction.
        unsafe {
            (*(agent as *mut AgentHandle))
                .in_use
                .store(false, Ordering::Release)
        };

        // SAFETY: byte ranges are valid; the null agent is the tested input.
        let null_rc = unsafe {
            opaque_agent_generate_ke1(
                ptr::null_mut(),
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                state,
                output.as_mut_ptr(),
                output.len(),
            )
        };

        assert_eq!(busy_rc, FFI_BUSY);
        assert_eq!(null_rc, OpaqueError::InvalidInput.to_c_int());
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut state);
            opaque_agent_destroy(&mut agent);
        }
    }

    #[test]
    fn live_handle_admission_rejects_overlap_but_independent_handle_progresses() {
        // SAFETY: helpers return live test-owned handles.
        let (mut first_agent, mut first_state) = unsafe { create_agent_and_state() };
        let (mut second_agent, mut second_state) = unsafe { create_agent_and_state() };
        let mut first_ke1 = [0u8; KE1_LENGTH];
        // SAFETY: all arguments satisfy the public contract and populate the first state.
        assert_eq!(
            unsafe {
                opaque_agent_generate_ke1(
                    first_agent,
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    first_state,
                    first_ke1.as_mut_ptr(),
                    first_ke1.len(),
                )
            },
            0
        );
        // SAFETY: the first state is live, quiescent, and test-owned.
        let first_state_ref = unsafe { &*(first_state as *const AgentStateHandle) };
        let private_before = *first_state_ref.state.initiator_ephemeral_private_key();
        let pq_before = *first_state_ref.state.pq_ephemeral_secret_key();
        assert!(!is_all_zero(&private_before));
        assert!(!is_all_zero(&pq_before));
        let shared_first_agent =
            std::sync::Arc::new(std::sync::atomic::AtomicPtr::new(first_agent));
        let holder_agent = std::sync::Arc::clone(&shared_first_agent);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let holder = std::thread::spawn(move || {
            let handle = holder_agent.load(Ordering::Acquire);
            let (_agent, guard) = acquire_agent(handle).expect("live handle admission");
            entered_tx.send(()).expect("entry notification");
            release_rx.recv().expect("release notification");
            drop(guard);
        });
        entered_rx.recv().expect("holder entered");

        let mut blocked_output = [0xA5u8; KE1_LENGTH];
        // SAFETY: byte ranges and state are valid; the first agent is deliberately admitted elsewhere.
        let blocked_rc = unsafe {
            opaque_agent_generate_ke1(
                first_agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                first_state,
                blocked_output.as_mut_ptr(),
                blocked_output.len(),
            )
        };

        let mut independent_output = [0u8; KE1_LENGTH];
        // SAFETY: all arguments for the independent handles satisfy the public contract.
        let independent_rc = unsafe {
            opaque_agent_generate_ke1(
                second_agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                second_state,
                independent_output.as_mut_ptr(),
                independent_output.len(),
            )
        };

        assert_eq!(blocked_rc, FFI_BUSY);
        assert!(blocked_output.iter().all(|byte| *byte == 0xA5));
        assert_eq!(independent_rc, 0);
        assert!(independent_output.iter().any(|byte| *byte != 0));
        // SAFETY: first state was never admitted by the rejected call.
        let first_state_ref = unsafe { &*(first_state as *const AgentStateHandle) };
        assert_eq!(first_state_ref.state.phase, InitiatorPhase::Ke1Generated);
        assert_eq!(
            first_state_ref.state.initiator_ephemeral_private_key(),
            &private_before
        );
        assert_eq!(first_state_ref.state.pq_ephemeral_secret_key(), &pq_before);
        println!(
            "DISPOSAL_CELL scenario=busy_rejection object=AgentStateHandle field=initiator_ephemeral_private_key entry=populated exit=busy expected=P observed=preserved"
        );
        println!(
            "DISPOSAL_CELL scenario=busy_rejection object=AgentStateHandle field=pq_ephemeral_secret_key entry=populated exit=busy expected=P observed=preserved"
        );

        release_tx.send(()).expect("release holder");
        holder.join().expect("holder thread");
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut first_state);
            opaque_agent_destroy(&mut first_agent);
            opaque_agent_state_destroy(&mut second_state);
            opaque_agent_destroy(&mut second_agent);
        }
    }

    #[test]
    fn detected_overlap_is_rejected_before_state_admission() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut aliased = [0xA5u8; KE1_LENGTH];

        // SAFETY: the allocation is live; intentional input/output overlap is detected before use.
        let rc = unsafe {
            opaque_agent_generate_ke1(
                agent,
                aliased.as_ptr(),
                16,
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                state,
                aliased.as_mut_ptr(),
                aliased.len(),
            )
        };

        assert_eq!(rc, OpaqueError::InvalidInput.to_c_int());
        assert!(aliased.iter().all(|byte| *byte == 0xA5));
        // SAFETY: state is live and quiescent.
        let state_ref = unsafe { &*(state as *const AgentStateHandle) };
        assert_eq!(state_ref.state.phase, InitiatorPhase::Created);
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut state);
            opaque_agent_destroy(&mut agent);
        }
    }

    #[test]
    fn larger_output_capacity_preserves_uncommitted_suffix() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut output = [0xA5u8; REGISTRATION_REQUEST_WIRE_LENGTH + 16];

        // SAFETY: all arguments satisfy the public contract and output capacity is intentionally larger.
        let rc = unsafe {
            opaque_agent_create_registration_request(
                agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                state,
                output.as_mut_ptr(),
                output.len(),
            )
        };

        assert_eq!(rc, 0);
        assert!(output[..REGISTRATION_REQUEST_WIRE_LENGTH]
            .iter()
            .any(|byte| *byte != 0xA5));
        assert!(output[REGISTRATION_REQUEST_WIRE_LENGTH..]
            .iter()
            .all(|byte| *byte == 0xA5));
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut state);
            opaque_agent_destroy(&mut agent);
        }
    }

    #[test]
    fn overlapping_finish_outputs_are_rejected_before_state_admission() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut output = [0xA5u8; HASH_LENGTH];

        // SAFETY: the allocation is live; intentional output/output overlap is detected before use.
        let rc = unsafe {
            opaque_agent_finish(
                agent,
                state,
                output.as_mut_ptr(),
                output.len(),
                output.as_mut_ptr(),
                EXPORT_KEY_LENGTH,
            )
        };

        assert_eq!(rc, OpaqueError::InvalidInput.to_c_int());
        assert!(output.iter().all(|byte| *byte == 0xA5));
        // SAFETY: state is live and quiescent.
        let state_ref = unsafe { &*(state as *const AgentStateHandle) };
        assert_eq!(state_ref.state.phase, InitiatorPhase::Created);
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut state);
            opaque_agent_destroy(&mut agent);
        }
    }

    #[test]
    fn admitted_error_terminalizes_state_and_preserves_output() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut first = [0u8; KE1_LENGTH];
        // SAFETY: all arguments satisfy the public contract.
        assert_eq!(
            unsafe {
                opaque_agent_generate_ke1(
                    agent,
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    state,
                    first.as_mut_ptr(),
                    first.len(),
                )
            },
            0
        );

        let mut sentinel = [0xA5u8; KE1_LENGTH];
        // SAFETY: all arguments satisfy the public contract; state reuse is the tested error.
        let rc = unsafe {
            opaque_agent_generate_ke1(
                agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                state,
                sentinel.as_mut_ptr(),
                sentinel.len(),
            )
        };

        assert_eq!(rc, OpaqueError::ValidationError.to_c_int());
        assert!(sentinel.iter().all(|byte| *byte == 0xA5));
        // SAFETY: state is live and quiescent.
        let state_ref = unsafe { &*(state as *const AgentStateHandle) };
        assert_eq!(state_ref.state.phase, InitiatorPhase::Finished);
        assert!(is_all_zero(
            state_ref.state.initiator_ephemeral_private_key()
        ));
        assert!(is_all_zero(state_ref.state.pq_ephemeral_secret_key()));
        // SAFETY: handles are live, quiescent, and test-owned.
        unsafe {
            opaque_agent_state_destroy(&mut state);
            opaque_agent_destroy(&mut agent);
        }
    }

    #[test]
    fn invalid_agent_operation_state_matrix_terminalizes_without_commit() {
        let phases = [
            InitiatorPhase::Created,
            InitiatorPhase::RegistrationRequested,
            InitiatorPhase::RegistrationFinalized,
            InitiatorPhase::Ke1Generated,
            InitiatorPhase::Ke3Generated,
            InitiatorPhase::Finished,
        ];
        let operations = [
            AgentStatefulOperation::RegistrationRequest,
            AgentStatefulOperation::FinalizeRegistration,
            AgentStatefulOperation::GenerateKe1,
            AgentStatefulOperation::GenerateKe3,
            AgentStatefulOperation::Finish,
        ];
        let response = [0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
        let ke2 = [0u8; KE2_LENGTH];
        let mut executed = 0usize;

        for phase in phases {
            for operation in operations {
                if is_legal_agent_cell(phase, operation) {
                    continue;
                }
                // SAFETY: helper returns live, test-owned handles for one matrix cell.
                let (mut agent, mut state) = unsafe { create_agent_and_state() };
                // SAFETY: this unit test owns the quiescent state and selects the matrix row.
                let fixture_ke3_exported = matches!(operation, AgentStatefulOperation::Finish);
                unsafe {
                    let state_ref = &mut *(state as *mut AgentStateHandle);
                    state_ref.state.phase = phase;
                    state_ref.ke3_exported = fixture_ke3_exported;
                }
                let mut primary = [0xA5u8; KE2_LENGTH];
                let mut secondary = [0xA5u8; EXPORT_KEY_LENGTH];

                // SAFETY: all descriptors are valid and disjoint; only the protocol phase is invalid.
                let rc = unsafe {
                    match operation {
                        AgentStatefulOperation::RegistrationRequest => {
                            opaque_agent_create_registration_request(
                                agent,
                                PASSWORD.as_ptr(),
                                PASSWORD.len(),
                                state,
                                primary.as_mut_ptr(),
                                primary.len(),
                            )
                        }
                        AgentStatefulOperation::FinalizeRegistration => {
                            opaque_agent_finalize_registration(
                                agent,
                                response.as_ptr(),
                                response.len(),
                                state,
                                primary.as_mut_ptr(),
                                primary.len(),
                            )
                        }
                        AgentStatefulOperation::GenerateKe1 => opaque_agent_generate_ke1(
                            agent,
                            PASSWORD.as_ptr(),
                            PASSWORD.len(),
                            ACCOUNT_ID.as_ptr(),
                            ACCOUNT_ID.len(),
                            state,
                            primary.as_mut_ptr(),
                            primary.len(),
                        ),
                        AgentStatefulOperation::GenerateKe3 => opaque_agent_generate_ke3(
                            agent,
                            ke2.as_ptr(),
                            ke2.len(),
                            state,
                            primary.as_mut_ptr(),
                            primary.len(),
                        ),
                        AgentStatefulOperation::Finish => opaque_agent_finish(
                            agent,
                            state,
                            primary.as_mut_ptr(),
                            primary.len(),
                            secondary.as_mut_ptr(),
                            secondary.len(),
                        ),
                    }
                };

                assert_eq!(
                    rc,
                    OpaqueError::ValidationError.to_c_int(),
                    "phase gate returned an unexpected status for {phase:?} × {operation:?}"
                );
                assert!(primary.iter().all(|byte| *byte == 0xA5));
                assert!(secondary.iter().all(|byte| *byte == 0xA5));
                // SAFETY: the admitted invalid-phase call leaves a live terminalized handle.
                let state_ref = unsafe { &*(state as *const AgentStateHandle) };
                assert_eq!(state_ref.state.phase, InitiatorPhase::Finished);
                println!(
                    "MATRIX_CELL side=agent phase={phase:?} operation={operation:?} relation=invalid_phase status={rc} output=unchanged post_phase=Finished fixture=phase_tag aux_ke3_exported={fixture_ke3_exported}"
                );
                executed += 1;

                // SAFETY: handles are live, quiescent, canonical, and test-owned.
                unsafe {
                    opaque_agent_state_destroy(&mut state);
                    opaque_agent_destroy(&mut agent);
                }
            }
        }

        assert_eq!(executed, 25);
    }

    #[test]
    fn caught_panic_terminalizes_state_and_preserves_output() {
        unsafe {
            let mut keypair = ptr::null_mut();
            assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);
            let mut relay_public_key = [0u8; PUBLIC_KEY_LENGTH];
            assert_eq!(
                opaque_relay_keypair_get_public_key(
                    keypair,
                    relay_public_key.as_mut_ptr(),
                    relay_public_key.len(),
                ),
                0
            );
            let mut relay = ptr::null_mut();
            assert_eq!(opaque_relay_create(keypair, &mut relay), 0);
            let mut agent = ptr::null_mut();
            assert_eq!(
                opaque_agent_create(
                    relay_public_key.as_ptr(),
                    relay_public_key.len(),
                    &mut agent,
                ),
                0
            );

            let mut registration_state = ptr::null_mut();
            assert_eq!(opaque_agent_state_create(&mut registration_state), 0);
            let mut registration_request = [0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
            assert_eq!(
                opaque_agent_create_registration_request(
                    agent,
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    registration_state,
                    registration_request.as_mut_ptr(),
                    registration_request.len(),
                ),
                0
            );
            let mut registration_response = [0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
            assert_eq!(
                opaque_relay_create_registration_response(
                    relay,
                    registration_request.as_ptr(),
                    registration_request.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    registration_response.as_mut_ptr(),
                    registration_response.len(),
                ),
                0
            );
            let mut registration_record = [0u8; REGISTRATION_RECORD_LENGTH];
            assert_eq!(
                opaque_agent_finalize_registration(
                    agent,
                    registration_response.as_ptr(),
                    registration_response.len(),
                    registration_state,
                    registration_record.as_mut_ptr(),
                    registration_record.len(),
                ),
                0
            );
            let mut credentials = [0u8; REGISTRATION_RECORD_LENGTH];
            assert_eq!(
                opaque_relay_build_credentials(
                    registration_record.as_ptr(),
                    registration_record.len(),
                    credentials.as_mut_ptr(),
                    credentials.len(),
                ),
                0
            );
            opaque_agent_state_destroy(&mut registration_state);

            let mut state = ptr::null_mut();
            let mut relay_state = ptr::null_mut();
            assert_eq!(opaque_agent_state_create(&mut state), 0);
            assert_eq!(opaque_relay_state_create(&mut relay_state), 0);
            let mut ke1 = [0u8; KE1_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke1(
                    agent,
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    state,
                    ke1.as_mut_ptr(),
                    ke1.len(),
                ),
                0
            );
            let mut ke2 = [0u8; KE2_LENGTH];
            assert_eq!(
                opaque_relay_generate_ke2(
                    relay,
                    ke1.as_ptr(),
                    ke1.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    credentials.as_ptr(),
                    credentials.len(),
                    ke2.as_mut_ptr(),
                    ke2.len(),
                    relay_state,
                ),
                0
            );
            let mut ke3 = [0u8; KE3_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke3(
                    agent,
                    ke2.as_ptr(),
                    ke2.len(),
                    state,
                    ke3.as_mut_ptr(),
                    ke3.len(),
                ),
                0
            );

            let mut session_sentinel = [0xA5u8; HASH_LENGTH];
            let mut export_sentinel = [0x5Au8; EXPORT_KEY_LENGTH];
            set_ffi_panic_point(Some("agent_finish_before_commit"));
            let rc = opaque_agent_finish(
                agent,
                state,
                session_sentinel.as_mut_ptr(),
                session_sentinel.len(),
                export_sentinel.as_mut_ptr(),
                export_sentinel.len(),
            );

            assert_eq!(rc, FFI_PANIC);
            assert!(session_sentinel.iter().all(|byte| *byte == 0xA5));
            assert!(export_sentinel.iter().all(|byte| *byte == 0x5A));
            let state_ref = &*(state as *const AgentStateHandle);
            assert_eq!(state_ref.state.phase, InitiatorPhase::Finished);
            assert!(!state_ref.ke3_exported);
            assert!(is_all_zero(
                state_ref.state.initiator_ephemeral_private_key()
            ));
            assert!(is_all_zero(state_ref.state.pq_ephemeral_secret_key()));
            println!(
                "TUPLE_COMMIT_CELL operation=agent_finish injection=before_commit status={rc} session=unchanged export=unchanged post_phase=Finished ke3_exported=false"
            );

            opaque_agent_state_destroy(&mut state);
            opaque_relay_state_destroy(&mut relay_state);
            opaque_agent_destroy(&mut agent);
            opaque_relay_destroy(&mut relay);
            opaque_relay_keypair_destroy(&mut keypair);
        }
    }

    #[test]
    fn destroy_observes_zeroized_populated_agent_state_storage() {
        // SAFETY: helper returns live test-owned handles.
        let (mut agent, mut state) = unsafe { create_agent_and_state() };
        let mut ke1 = [0u8; KE1_LENGTH];
        // SAFETY: all arguments satisfy the public contract.
        assert_eq!(
            unsafe {
                opaque_agent_generate_ke1(
                    agent,
                    PASSWORD.as_ptr(),
                    PASSWORD.len(),
                    ACCOUNT_ID.as_ptr(),
                    ACCOUNT_ID.len(),
                    state,
                    ke1.as_mut_ptr(),
                    ke1.len(),
                )
            },
            0
        );
        // SAFETY: the state is live and quiescent before destruction.
        let state_ref = unsafe { &*(state as *const AgentStateHandle) };
        assert!(!is_all_zero(
            state_ref.state.initiator_ephemeral_private_key()
        ));
        assert!(!is_all_zero(state_ref.state.pq_ephemeral_secret_key()));

        take_disposal_observations();
        // SAFETY: the state is live, quiescent, canonical, and test-owned.
        unsafe { opaque_agent_state_destroy(&mut state) };
        let observations = take_disposal_observations();
        let observation = observations
            .iter()
            .find(|item| item.object == "AgentStateHandle")
            .expect("agent state disposal observation");
        assert!(observation.fields.iter().all(|(_, erased)| *erased));
        for field in ["initiator_ephemeral_private_key", "pq_ephemeral_secret_key"] {
            let erased = observation
                .fields
                .iter()
                .find(|(name, _)| *name == field)
                .map(|(_, erased)| *erased)
                .expect("designated agent disposal field");
            assert!(erased);
            println!(
                "DISPOSAL_CELL scenario=agent_state_destroy object=AgentStateHandle field={field} entry=populated exit=destroy expected=E observed=overwritten"
            );
        }

        // SAFETY: handle is live, quiescent, and test-owned.
        unsafe { opaque_agent_destroy(&mut agent) };
    }
}
