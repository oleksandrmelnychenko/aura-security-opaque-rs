// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Relay (Server) FFI — for backend integration
//!
//! This module provides the server-side OPAQUE API. A typical backend service
//! calls these functions through C FFI (e.g., from Go via cgo, from Node.js
//! via N-API, or from any language with C interop).
//!
//! ## Lifecycle overview
//!
//! ```text
//! ┌─────────────────── SERVER SETUP ────────────────────┐
//! │                                                      │
//! │ OPTION A — Generate fresh keypair:                   │
//! │   opaque_relay_keypair_generate(&kp_handle)          │
//! │   opaque_relay_keypair_get_public_key(               │
//! │       kp_handle, &public_key[32], 32)                │
//! │   opaque_relay_create(kp_handle, &relay_handle)      │
//! │                                                      │
//! │ OPTION B — Restore from stored keys:                 │
//! │   opaque_relay_create_with_keys(                     │
//! │       private_key, 32,                               │
//! │       public_key, 32,                                │
//! │       oprf_seed, 32,                                 │
//! │       &relay_handle)                                 │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌────────── REGISTRATION (when client signs up) ──────┐
//! │                                                      │
//! │ ◄─── receive request[33] + account_id from client    │
//! │                                                      │
//! │ opaque_relay_create_registration_response(            │
//! │     relay_handle,                                    │
//! │     request, 33,                                     │
//! │     account_id, account_id_len,                      │
//! │     &response[65], 65)                               │
//! │                                                      │
//! │ ──── send response[65] to client ────►               │
//! │ ◄─── receive record[201] from client                 │
//! │                                                      │
//! │ Store record[201] in database keyed by account_id    │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌────────── AUTHENTICATION (each login) ──────────────┐
//! │                                                      │
//! │ ◄─── receive ke1[1273] + account_id from client      │
//! │                                                      │
//! │ Load record[201] from database (required)            │
//! │                                                      │
//! │ opaque_relay_state_create(&state_handle)              │
//! │                                                      │
//! │ opaque_relay_generate_ke2(                           │
//! │     relay_handle,                                    │
//! │     ke1, 1273,                                       │
//! │     account_id, account_id_len,                      │
//! │     record_or_null, record_len_or_0,                 │
//! │     &ke2[1377], 1377,                                │
//! │     state_handle)                                    │
//! │                                                      │
//! │ ──── send ke2[1377] to client ────►                  │
//! │ ◄─── receive ke3[65] from client                     │
//! │                                                      │
//! │ opaque_relay_finish(                                 │
//! │     relay_handle,                                    │
//! │     ke3, 65,                                         │
//! │     state_handle,                                    │
//! │     &session_key[64], 64)                            │
//! │                                                      │
//! │ opaque_relay_state_destroy(&state_handle)             │
//! └──────────────────────────────────────────────────────┘
//!
//! ┌─────────────────── CLEANUP ─────────────────────────┐
//! │ opaque_relay_destroy(&relay_handle)                   │
//! │ opaque_relay_keypair_destroy(&kp_handle)              │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Strict credential requirements
//!
//! `opaque_relay_generate_ke2` accepts either a valid persisted credential record
//! or `NULL, 0` for unknown accounts. In the latter case it derives deterministic
//! fake credentials and still returns a syntactically valid KE2 to avoid account
//! enumeration via response shape or timing.

use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::{Zeroize, Zeroizing};

use opaque_core::protocol;
use opaque_core::types::{
    pq, OpaqueError, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH, OPRF_SEED_LENGTH,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
    REGISTRATION_REQUEST_WIRE_LENGTH, REGISTRATION_RESPONSE_WIRE_LENGTH,
    RESPONDER_CREDENTIALS_LENGTH,
};
use opaque_relay::{
    build_credentials, create_registration_response, generate_ke2, responder_finish, Ke2Message,
    OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderKeyPair, ResponderState,
};

use crate::{
    ffi_error_to_int, handle_access_to_int, inject_test_panic, ranges_overlap, HandleAccessError,
};

const FFI_PANIC: i32 = -99;

const FFI_BUSY: i32 = -100;
const FFI_CORRUPTED_RECORD: i32 = -101;

const MAX_ACCOUNT_ID_LENGTH: usize = 1024;

struct RelayHandle {
    responder: OpaqueResponder,
    in_use: AtomicBool,
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.responder.zeroize();
        #[cfg(test)]
        crate::record_disposal_observation(
            "RelayHandle",
            vec![(
                "static_private_key",
                opaque_core::types::is_all_zero(&self.responder.keypair().private_key),
            )],
        );
    }
}

struct RelayStateHandle {
    state: ResponderState,
    in_use: AtomicBool,
}

impl Drop for RelayStateHandle {
    fn drop(&mut self) {
        self.state.zeroize();
        #[cfg(test)]
        crate::record_disposal_observation(
            "RelayStateHandle",
            vec![
                (
                    "responder_private_key",
                    opaque_core::types::is_all_zero(self.state.responder_private_key()),
                ),
                (
                    "responder_ephemeral_private_key",
                    opaque_core::types::is_all_zero(self.state.responder_ephemeral_private_key()),
                ),
                (
                    "session_key",
                    opaque_core::types::is_all_zero(self.state.session_key()),
                ),
                (
                    "expected_initiator_mac",
                    opaque_core::types::is_all_zero(self.state.expected_initiator_mac()),
                ),
                (
                    "pq_shared_secret",
                    opaque_core::types::is_all_zero(self.state.pq_shared_secret()),
                ),
            ],
        );
    }
}

struct RelayKeypairHandle {
    keypair: ResponderKeyPair,
    oprf_seed: [u8; OPRF_SEED_LENGTH],
    in_use: AtomicBool,
}

impl Drop for RelayKeypairHandle {
    fn drop(&mut self) {
        self.keypair.zeroize();
        self.oprf_seed.zeroize();
        #[cfg(test)]
        crate::record_disposal_observation(
            "RelayKeypairHandle",
            vec![
                (
                    "static_private_key",
                    opaque_core::types::is_all_zero(&self.keypair.private_key),
                ),
                (
                    "oprf_seed",
                    opaque_core::types::is_all_zero(&self.oprf_seed),
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

fn acquire_relay(
    handle: *const std::ffi::c_void,
) -> Result<(&'static RelayHandle, BusyGuard<'static>), HandleAccessError> {
    if handle.is_null() {
        return Err(HandleAccessError::InvalidHandle);
    }
    let ptr = handle as *const RelayHandle;
    // SAFETY: the public contract requires a live RelayHandle created by this library.
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

fn acquire_relay_state(
    handle: *mut std::ffi::c_void,
) -> Result<(&'static mut RelayStateHandle, BusyGuard<'static>), HandleAccessError> {
    if handle.is_null() {
        return Err(HandleAccessError::InvalidHandle);
    }
    let ptr = handle as *mut RelayStateHandle;
    // SAFETY: the public contract requires a live RelayStateHandle created by this library.
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

fn invalidate_relay_state(state_handle: &mut RelayStateHandle) {
    state_handle.state.invalidate();
}

fn acquire_relay_keypair(
    handle: *mut std::ffi::c_void,
) -> Result<(&'static RelayKeypairHandle, BusyGuard<'static>), HandleAccessError> {
    if handle.is_null() {
        return Err(HandleAccessError::InvalidHandle);
    }
    let ptr = handle as *const RelayKeypairHandle;
    // SAFETY: the public contract requires a live RelayKeypairHandle created by this library.
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

fn run_relay_stateful(
    state_handle: &mut RelayStateHandle,
    operation: impl FnOnce(&mut RelayStateHandle) -> opaque_core::types::OpaqueResult<()>,
) -> i32 {
    match panic::catch_unwind(AssertUnwindSafe(|| operation(state_handle))) {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            invalidate_relay_state(state_handle);
            ffi_error_to_int(error)
        }
        Err(_) => {
            invalidate_relay_state(state_handle);
            FFI_PANIC
        }
    }
}

/// Generates a fresh Ristretto255 keypair and a random 32-byte OPRF seed.
///
/// The keypair and OPRF seed are stored inside the returned handle. Use
/// [`opaque_relay_keypair_get_public_key`] to extract the public key (which must be
/// distributed to clients), and [`opaque_relay_create`] to create a relay handle from it.
///
/// **Important:** The private key and OPRF seed must be persisted securely (e.g., in a
/// vault or HSM) if you need the server to survive restarts. Use
/// [`opaque_relay_create_with_keys`] to restore from stored keys.
///
/// # Parameters
///
/// | Name     | Type            | Description                                |
/// |----------|-----------------|------------------------------------------- |
/// | `handle` | `*mut *mut void`| Receives the new keypair handle (out-param)|
///
/// # Returns
///
/// `0` on success. The caller must free the handle with [`opaque_relay_keypair_destroy`].
///
/// # Safety
///
/// `handle` must be a valid, non-null pointer to a `*mut c_void` that will receive the newly
/// allocated keypair handle. The caller owns the returned handle and must free it with
/// `opaque_relay_keypair_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_generate(handle: *mut *mut std::ffi::c_void) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        let Ok(keypair) = ResponderKeyPair::generate() else {
            return ffi_error_to_int(OpaqueError::CryptoError);
        };
        let mut oprf_seed = Zeroizing::new([0u8; OPRF_SEED_LENGTH]);
        if opaque_core::crypto::random_bytes(&mut *oprf_seed).is_err() {
            return ffi_error_to_int(OpaqueError::CryptoError);
        }
        let boxed = Box::new(RelayKeypairHandle {
            keypair,
            oprf_seed: *oprf_seed,
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("relay_keypair_generate_before_publish");
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Destroys a keypair handle, securely zeroizing the private key and OPRF seed.
///
/// # Safety
///
/// `handle_ptr` must be a valid, non-null pointer to a `*mut c_void` that was
/// previously set by `opaque_relay_keypair_generate`. After this call the inner
/// pointer is set to null, preventing double-free. The caller must ensure that destruction does
/// not overlap any operation through this handle or a copied alias.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_destroy(handle_ptr: *mut *mut std::ffi::c_void) {
    let _ = opaque_relay_keypair_try_destroy(handle_ptr);
}

/// Tries to destroy a relay keypair handle and reports the outcome.
///
/// Returns:
/// - `0` on success or if handle is already null.
/// - `-1` if `handle_ptr` is null.
/// - `-100` if the handle is currently in use by another call.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_try_destroy(
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
        let in_use = &(*(handle as *const RelayKeypairHandle)).in_use;
        if in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        // SAFETY: external quiescence and canonical-slot ownership are caller obligations.
        drop(unsafe { Box::from_raw(handle as *mut RelayKeypairHandle) });
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Copies the relay's 32-byte public key into the provided buffer.
///
/// This public key must be distributed to all clients (e.g., pinned in the app binary
/// or served over a trusted TLS channel). Clients pass it to `opaque_agent_create`.
///
/// # Parameters
///
/// | Name              | Type        | Size  | Description                           |
/// |-------------------|-------------|-------|---------------------------------------|
/// | `handle`          | `*mut void` | —     | Keypair handle                        |
/// | `public_key`      | `*mut u8`   | ≥ 32  | Output buffer for the public key      |
/// | `key_buffer_size` | `usize`     | —     | Size of output buffer (must be ≥ 32)  |
///
/// # Returns
///
/// `0` on success. The 32-byte public key is written to `public_key`.
///
/// # Safety
///
/// `handle` must be a valid, non-null pointer to a `RelayKeypairHandle` previously returned
/// by `opaque_relay_keypair_generate`. `public_key` must point to a buffer of at least
/// `PUBLIC_KEY_LENGTH` (32) bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_get_public_key(
    handle: *mut std::ffi::c_void,
    public_key: *mut u8,
    key_buffer_size: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if public_key.is_null() || key_buffer_size < PUBLIC_KEY_LENGTH {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let (kh, _kg) = match acquire_relay_keypair(handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let public_key_copy = kh.keypair.public_key;
        inject_test_panic("relay_keypair_public_key_before_commit");
        // SAFETY: the output contract requires a writable range of PUBLIC_KEY_LENGTH bytes.
        ptr::copy_nonoverlapping(public_key_copy.as_ptr(), public_key, PUBLIC_KEY_LENGTH);
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Creates a relay handle from a previously generated keypair.
///
/// The relay handle is the main server-side object used for registration and
/// authentication. It holds the static keypair and the OPRF evaluator.
///
/// # Parameters
///
/// | Name             | Type            | Description                              |
/// |------------------|-----------------|------------------------------------------|
/// | `keypair_handle` | `*mut void`     | Keypair from `opaque_relay_keypair_generate` |
/// | `handle`         | `*mut *mut void`| Receives the new relay handle (out-param)|
///
/// # Returns
///
/// `0` on success. The caller must free the relay with [`opaque_relay_destroy`].
///
/// # Safety
///
/// `keypair_handle` must be a valid pointer to a `RelayKeypairHandle` from
/// `opaque_relay_keypair_generate`. `handle` must be a valid, non-null pointer to a
/// `*mut c_void` that will receive the new relay handle. The caller owns the returned handle
/// and must free it with `opaque_relay_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create(
    keypair_handle: *mut std::ffi::c_void,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        let (kh, _kg) = match acquire_relay_keypair(keypair_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let result = OpaqueResponder::new(kh.keypair.clone(), kh.oprf_seed);
        drop(_kg);
        let Ok(responder) = result else {
            return OpaqueError::InvalidInput.to_c_int();
        };
        let boxed = Box::new(RelayHandle {
            responder,
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("relay_create_before_publish");
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Destroys a relay handle, securely zeroizing the private key and OPRF state.
///
/// # Safety
///
/// `handle_ptr` must be a valid, non-null pointer to a `*mut c_void` that was
/// previously set by `opaque_relay_create` or `opaque_relay_create_with_keys`.
/// After this call the inner pointer is set to null, preventing double-free. The caller must
/// ensure that destruction does not overlap any operation through this handle or a copied alias.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_destroy(handle_ptr: *mut *mut std::ffi::c_void) {
    let _ = opaque_relay_try_destroy(handle_ptr);
}

/// Tries to destroy a relay handle and reports the outcome.
///
/// Returns:
/// - `0` on success or if handle is already null.
/// - `-1` if `handle_ptr` is null.
/// - `-100` if the handle is currently in use by another call.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_try_destroy(handle_ptr: *mut *mut std::ffi::c_void) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle_ptr.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        let handle = *handle_ptr;
        if handle.is_null() {
            return 0;
        }
        let in_use = &(*(handle as *const RelayHandle)).in_use;
        if in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        // SAFETY: external quiescence and canonical-slot ownership are caller obligations.
        drop(unsafe { Box::from_raw(handle as *mut RelayHandle) });
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Allocates a fresh relay state for one authentication session.
///
/// Each login attempt requires its own state. The state has a **5-minute lifetime**.
///
/// # Parameters
///
/// | Name     | Type            | Description                             |
/// |----------|-----------------|---------------------------------------- |
/// | `handle` | `*mut *mut void`| Receives the new state handle (out-param)|
///
/// # Returns
///
/// `0` on success. The caller must free the state with [`opaque_relay_state_destroy`].
///
/// # Safety
///
/// `handle` must be a valid, non-null pointer to a `*mut c_void` that will receive the newly
/// allocated state. The caller owns the returned handle and must free it with
/// `opaque_relay_state_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_state_create(handle: *mut *mut std::ffi::c_void) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        let boxed = Box::new(RelayStateHandle {
            state: ResponderState::new(),
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("relay_state_create_before_publish");
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Destroys a relay state handle, securely zeroizing session keys and ephemeral material.
///
/// # Safety
///
/// `handle_ptr` must be a valid, non-null pointer to a `*mut c_void` that was
/// previously set by `opaque_relay_state_create`. After this call the inner
/// pointer is set to null, preventing double-free. The caller must ensure that destruction does
/// not overlap any operation through this state handle or a copied alias.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_state_destroy(handle_ptr: *mut *mut std::ffi::c_void) {
    let _ = opaque_relay_state_try_destroy(handle_ptr);
}

/// Tries to destroy a relay state handle and reports the outcome.
///
/// Returns:
/// - `0` on success or if handle is already null.
/// - `-1` if `handle_ptr` is null.
/// - `-100` if the handle is currently in use by another call.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_state_try_destroy(
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
        let in_use = &(*(handle as *const RelayStateHandle)).in_use;
        if in_use
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return FFI_BUSY;
        }
        *handle_ptr = ptr::null_mut();
        // SAFETY: external quiescence and canonical-slot ownership are caller obligations.
        drop(unsafe { Box::from_raw(handle as *mut RelayStateHandle) });
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Registration step (server side).** Evaluates the client's blinded OPRF request
/// and returns a 65-byte registration response.
///
/// The response contains a version prefix (1 byte), the OPRF-evaluated element (32 bytes),
/// and the server's static public key (32 bytes). Send it back to the client.
///
/// # Parameters
///
/// | Name                  | Type          | Size   | Description                              |
/// |-----------------------|---------------|--------|------------------------------------------|
/// | `relay_handle`        | `*const void` | —      | Relay handle from `opaque_relay_create`  |
/// | `request_data`        | `*const u8`   | 33     | Client's blinded registration request    |
/// | `request_length`      | `usize`       | —      | Must be exactly 33                       |
/// | `account_id`          | `*const u8`   | ≥ 1    | Unique account identifier (e.g., email)  |
/// | `account_id_length`   | `usize`       | —      | Length of account_id in bytes            |
/// | `response_data`       | `*mut u8`     | ≥ 65   | Output buffer for registration response  |
/// | `response_buffer_size`| `usize`       | —      | Size of output buffer (must be ≥ 65)     |
///
/// # Returns
///
/// `0` on success. The 65-byte response is written to `response_data`.
///
/// # Safety
///
/// - `relay_handle` must be a valid pointer to a `RelayHandle` from `opaque_relay_create`.
/// - `request_data` must point to at least `REGISTRATION_REQUEST_WIRE_LENGTH` (33) readable bytes.
/// - `account_id` must point to at least `account_id_length` readable bytes (non-zero).
/// - `response_data` must point to a writable buffer of at least
///   `REGISTRATION_RESPONSE_WIRE_LENGTH` (65) bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create_registration_response(
    relay_handle: *const std::ffi::c_void,
    request_data: *const u8,
    request_length: usize,
    account_id: *const u8,
    account_id_length: usize,
    response_data: *mut u8,
    response_buffer_size: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if request_data.is_null()
            || request_length != REGISTRATION_REQUEST_WIRE_LENGTH
            || account_id.is_null()
            || account_id_length == 0
            || account_id_length > MAX_ACCOUNT_ID_LENGTH
            || response_data.is_null()
            || response_buffer_size < REGISTRATION_RESPONSE_WIRE_LENGTH
            || ranges_overlap(
                request_data,
                request_length,
                response_data.cast_const(),
                REGISTRATION_RESPONSE_WIRE_LENGTH,
            )
            || ranges_overlap(
                account_id,
                account_id_length,
                response_data.cast_const(),
                REGISTRATION_RESPONSE_WIRE_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (rh, _rg) = match acquire_relay(relay_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        // SAFETY: validated readable extents are part of the public ABI contract.
        let req = unsafe { std::slice::from_raw_parts(request_data, request_length) };
        let aid = unsafe { std::slice::from_raw_parts(account_id, account_id_length) };
        let mut response = RegistrationResponse::new();

        match create_registration_response(&rh.responder, req, aid, &mut response) {
            Ok(()) => {
                let mut wire = Zeroizing::new([0u8; REGISTRATION_RESPONSE_WIRE_LENGTH]);
                if let Err(error) = protocol::write_registration_response(
                    &response.data[..PUBLIC_KEY_LENGTH],
                    &response.data[PUBLIC_KEY_LENGTH..],
                    &mut *wire,
                ) {
                    return ffi_error_to_int(error);
                }
                inject_test_panic("relay_registration_response_before_commit");
                // SAFETY: output was validated as writable, sufficiently large, and disjoint.
                unsafe {
                    ptr::copy_nonoverlapping(
                        wire.as_ptr(),
                        response_data,
                        REGISTRATION_RESPONSE_WIRE_LENGTH,
                    )
                };
                0
            }
            Err(e) => ffi_error_to_int(e),
        }
    }))
    .unwrap_or(FFI_PANIC)
}

/// Parses a 201-byte registration record into credentials for use in authentication.
///
/// Call this after receiving the registration record from the client and loading it
/// from the database. The output `credentials_out` (201 bytes) is passed to
/// `opaque_relay_generate_ke2` during authentication.
///
/// # Parameters
///
/// | Name                  | Type        | Size   | Description                              |
/// |-----------------------|-------------|--------|------------------------------------------|
/// | `registration_record` | `*const u8` | 201    | Record received from client at registration |
/// | `record_length`       | `usize`     | —      | Must be exactly 201                      |
/// | `credentials_out`     | `*mut u8`   | ≥ 201  | Output buffer for parsed credentials     |
/// | `credentials_out_length`| `usize`   | —      | Size of output buffer (must be ≥ 201)    |
///
/// # Returns
///
/// `0` on success. Returns `-7` if the record indicates the account is already registered
/// in the credential store.
///
/// # Safety
///
/// - `registration_record` must point to at least `REGISTRATION_RECORD_LENGTH` readable bytes.
/// - `credentials_out` must point to a writable buffer of at least
///   `RESPONDER_CREDENTIALS_LENGTH` bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_build_credentials(
    registration_record: *const u8,
    record_length: usize,
    credentials_out: *mut u8,
    credentials_out_length: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if registration_record.is_null()
            || record_length != REGISTRATION_RECORD_LENGTH
            || credentials_out.is_null()
            || credentials_out_length < RESPONDER_CREDENTIALS_LENGTH
            || ranges_overlap(
                registration_record,
                record_length,
                credentials_out.cast_const(),
                RESPONDER_CREDENTIALS_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        // SAFETY: validated readable extent is part of the public ABI contract.
        let record = unsafe { std::slice::from_raw_parts(registration_record, record_length) };
        let mut creds = ResponderCredentials::new();

        match build_credentials(record, &mut creds) {
            Ok(()) => {}
            Err(e) => return ffi_error_to_int(e),
        }
        let mut credential_storage =
            Zeroizing::new([0u8; opaque_core::types::REGISTRATION_CREDENTIAL_LENGTH]);
        credential_storage[..opaque_core::types::MASKING_KEY_LENGTH]
            .copy_from_slice(&creds.masking_key);
        credential_storage[opaque_core::types::MASKING_KEY_LENGTH..]
            .copy_from_slice(&creds.envelope);
        let mut wire = Zeroizing::new([0u8; RESPONDER_CREDENTIALS_LENGTH]);
        let write_result = protocol::write_registration_record(
            &*credential_storage,
            &creds.initiator_public_key,
            &mut *wire,
        );
        if let Err(error) = write_result {
            return ffi_error_to_int(error);
        }
        inject_test_panic("relay_build_credentials_before_commit");
        // SAFETY: output was validated as writable, sufficiently large, and disjoint.
        unsafe {
            ptr::copy_nonoverlapping(wire.as_ptr(), credentials_out, RESPONDER_CREDENTIALS_LENGTH)
        };
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 1/2 (server side).** Processes the client's KE1 and produces KE2.
///
/// This performs the server's half of the key exchange:
/// 1. Evaluates the OPRF on the client's blinded request
/// 2. Generates an ephemeral Ristretto255 keypair and nonce
/// 3. Performs 4-way Diffie-Hellman (3DH + ephemeral-ephemeral)
/// 4. Encapsulates a shared secret via ML-KEM-768
/// 5. Combines classical and post-quantum key material (AND-model)
/// 6. Computes the server's MAC for mutual authentication
///
/// # Parameters
///
/// | Name                | Type          | Size   | Description                              |
/// |---------------------|---------------|--------|------------------------------------------|
/// | `relay_handle`      | `*const void` | —      | Relay handle from `opaque_relay_create`  |
/// | `ke1_data`          | `*const u8`   | 1273   | Client's KE1 message                    |
/// | `ke1_length`        | `usize`       | —      | Must be exactly 1273                     |
/// | `account_id`        | `*const u8`   | ≥ 1    | Account identifier for OPRF key derivation|
/// | `account_id_length` | `usize`       | —      | Length of account_id in bytes            |
/// | `credentials_data`  | `*const u8`   | 201/0   | Stored credentials, or `NULL` for unknown user |
/// | `credentials_length`| `usize`       | —      | Must be exactly 201, or 0 for unknown user |
/// | `ke2_data`          | `*mut u8`     | ≥ 1377 | Output buffer for KE2 message            |
/// | `ke2_buffer_size`   | `usize`       | —      | Size of output buffer (must be ≥ 1377)   |
/// | `state_handle`      | `*mut void`   | —      | Fresh state from `opaque_relay_state_create`|
///
/// # Returns
///
/// `0` on success. The 1377-byte KE2 is written to `ke2_data`.
/// Returns `-101` when a non-null `credentials_data` buffer cannot be parsed as a valid
/// registration record.
///
/// # Safety
///
/// - `relay_handle` must be a valid pointer to a `RelayHandle` from `opaque_relay_create`.
/// - `ke1_data` must point to at least `KE1_LENGTH` readable bytes.
/// - `account_id` must point to at least `account_id_length` readable bytes (non-zero).
/// - `credentials_data` must point to at least `RESPONDER_CREDENTIALS_LENGTH` readable bytes
///   when `credentials_length != 0`. Pass `NULL, 0` to execute the unknown-user fake-credential path.
/// - `ke2_data` must point to a writable buffer of at least `KE2_LENGTH` bytes.
/// - `state_handle` must be a valid pointer to a `RelayStateHandle` from
///   `opaque_relay_state_create`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_generate_ke2(
    relay_handle: *const std::ffi::c_void,
    ke1_data: *const u8,
    ke1_length: usize,
    account_id: *const u8,
    account_id_length: usize,
    credentials_data: *const u8,
    credentials_length: usize,
    ke2_data: *mut u8,
    ke2_buffer_size: usize,
    state_handle: *mut std::ffi::c_void,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if ke1_data.is_null()
            || ke1_length != KE1_LENGTH
            || account_id.is_null()
            || account_id_length == 0
            || account_id_length > MAX_ACCOUNT_ID_LENGTH
            || ke2_data.is_null()
            || ke2_buffer_size < KE2_LENGTH
            || ranges_overlap(ke1_data, ke1_length, ke2_data.cast_const(), KE2_LENGTH)
            || ranges_overlap(
                account_id,
                account_id_length,
                ke2_data.cast_const(),
                KE2_LENGTH,
            )
        {
            return OpaqueError::InvalidInput.to_c_int();
        }
        match credentials_length {
            0 => {}
            RESPONDER_CREDENTIALS_LENGTH => {
                if credentials_data.is_null() {
                    return OpaqueError::InvalidInput.to_c_int();
                }
                if ranges_overlap(
                    credentials_data,
                    credentials_length,
                    ke2_data.cast_const(),
                    KE2_LENGTH,
                ) {
                    return OpaqueError::InvalidInput.to_c_int();
                }
            }
            _ => return OpaqueError::InvalidInput.to_c_int(),
        }

        let (rh, _rg) = match acquire_relay(relay_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        let mut credential_wire = Zeroizing::new([0u8; RESPONDER_CREDENTIALS_LENGTH]);
        match credentials_length {
            RESPONDER_CREDENTIALS_LENGTH => {
                // SAFETY: validated readable extent is part of the public ABI contract.
                let input =
                    unsafe { std::slice::from_raw_parts(credentials_data, credentials_length) };
                credential_wire.copy_from_slice(input);
            }
            0 => {
                let fake_credentials = [0u8; opaque_core::types::REGISTRATION_CREDENTIAL_LENGTH];
                let fake_public_key = rh.responder.public_key();
                if protocol::write_registration_record(
                    &fake_credentials,
                    fake_public_key,
                    &mut *credential_wire,
                )
                .is_err()
                {
                    return OpaqueError::InvalidInput.to_c_int();
                }
            }
            _ => return OpaqueError::InvalidInput.to_c_int(),
        }

        let record_view = match protocol::parse_registration_record(&*credential_wire) {
            Ok(view) => view,
            Err(_) => return FFI_CORRUPTED_RECORD,
        };
        if opaque_core::crypto::validate_public_key(record_view.initiator_public_key).is_err()
            || record_view.envelope.len() != opaque_core::types::ENVELOPE_LENGTH
            || record_view.masking_key.len() != opaque_core::types::MASKING_KEY_LENGTH
        {
            return FFI_CORRUPTED_RECORD;
        }

        let mut creds = ResponderCredentials::new();
        match credentials_length {
            RESPONDER_CREDENTIALS_LENGTH => {
                creds.envelope = record_view.envelope.to_vec();
                creds.masking_key.copy_from_slice(record_view.masking_key);
                creds
                    .initiator_public_key
                    .copy_from_slice(record_view.initiator_public_key);
                creds.registered = true;
            }
            0 => {}
            _ => return OpaqueError::InvalidInput.to_c_int(),
        }

        let (sh, _sg) = match acquire_relay_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_relay_stateful(sh, |sh| {
            // SAFETY: validated readable extents are part of the public ABI contract.
            let ke1 = unsafe { std::slice::from_raw_parts(ke1_data, ke1_length) };
            let aid = unsafe { std::slice::from_raw_parts(account_id, account_id_length) };
            let mut ke2 = Ke2Message::new();
            generate_ke2(&rh.responder, ke1, aid, &creds, &mut ke2, &mut sh.state)?;

            let mut wire = Zeroizing::new([0u8; KE2_LENGTH]);
            protocol::write_ke2(
                &ke2.responder_nonce,
                &ke2.responder_public_key,
                &ke2.credential_response,
                &ke2.responder_mac,
                &ke2.kem_ciphertext,
                &mut *wire,
            )?;
            inject_test_panic("relay_generate_ke2_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe { ptr::copy_nonoverlapping(wire.as_ptr(), ke2_data, KE2_LENGTH) };
            Ok(())
        })
    }))
    .unwrap_or(FFI_PANIC)
}

/// **Authentication step 2/2 (server side).** Verifies the client's KE3 MAC and
/// extracts the shared session key.
///
/// If the MAC is valid, the handshake is complete and both sides share identical
/// session key (64 bytes). Durable client export keys are never available to the relay.
///
/// After this call, all ephemeral state is securely zeroized.
///
/// # Parameters
///
/// | Name                     | Type        | Size   | Description                           |
/// |--------------------------|-------------|--------|---------------------------------------|
/// | `_relay_handle`          | `*const void`| —     | Reserved (pass the relay handle)      |
/// | `ke3_data`               | `*const u8` | 65     | Client's KE3 message                 |
/// | `ke3_length`             | `usize`     | —      | Must be exactly 65                    |
/// | `state_handle`           | `*mut void` | —      | Same state used in `generate_ke2`     |
/// | `session_key`            | `*mut u8`   | ≥ 64   | Output: 64-byte session key           |
/// | `session_key_buffer_size`| `usize`     | —      | Must be ≥ 64                          |
///
/// # Returns
///
/// `0` on success (client authenticated). Returns `-5` if the client's MAC is invalid
/// (wrong password or tampered KE3).
///
/// # Safety
///
/// - `ke3_data` must point to at least `KE3_LENGTH` readable bytes.
/// - `state_handle` must be a valid pointer to a `RelayStateHandle` that was used in a prior
///   `opaque_relay_generate_ke2` call.
/// - `session_key` must point to a writable buffer of at least `HASH_LENGTH` (64) bytes.
///   bytes.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_finish(
    relay_handle: *const std::ffi::c_void,
    ke3_data: *const u8,
    ke3_length: usize,
    state_handle: *mut std::ffi::c_void,
    session_key: *mut u8,
    session_key_buffer_size: usize,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if ke3_data.is_null()
            || ke3_length != KE3_LENGTH
            || session_key.is_null()
            || session_key_buffer_size < HASH_LENGTH
            || ranges_overlap(ke3_data, ke3_length, session_key.cast_const(), HASH_LENGTH)
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        let (_rh, _rg) = match acquire_relay(relay_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };
        let (sh, _sg) = match acquire_relay_state(state_handle) {
            Ok(value) => value,
            Err(error) => return handle_access_to_int(error),
        };

        run_relay_stateful(sh, |sh| {
            // SAFETY: validated readable extent is part of the public ABI contract.
            let ke3 = unsafe { std::slice::from_raw_parts(ke3_data, ke3_length) };
            let mut sk = Zeroizing::new([0u8; HASH_LENGTH]);
            responder_finish(ke3, &mut sh.state, &mut sk)?;
            inject_test_panic("relay_finish_before_commit");
            // SAFETY: output was validated as writable, sufficiently large, and disjoint.
            unsafe { ptr::copy_nonoverlapping(sk.as_ptr(), session_key, HASH_LENGTH) };
            Ok(())
        })
    }))
    .unwrap_or(FFI_PANIC)
}

/// Creates a relay handle from pre-existing key material (for server restarts).
///
/// Use this instead of `opaque_relay_keypair_generate` + `opaque_relay_create` when
/// restoring from persisted keys. All three components (private key, public key, OPRF seed)
/// must be the same ones used during registration — otherwise existing users cannot
/// authenticate.
///
/// # Parameters
///
/// | Name            | Type            | Size | Description                               |
/// |-----------------|-----------------|------|-------------------------------------------|
/// | `private_key`   | `*const u8`     | 32   | Ristretto255 private key (scalar)         |
/// | `private_key_len`| `usize`        | —    | Must be exactly 32                        |
/// | `public_key`    | `*const u8`     | 32   | Ristretto255 public key (compressed point)|
/// | `public_key_len`| `usize`         | —    | Must be exactly 32                        |
/// | `oprf_seed_ptr` | `*const u8`     | 32   | OPRF seed for per-account key derivation  |
/// | `oprf_seed_len` | `usize`         | —    | Must be exactly 32                        |
/// | `handle`        | `*mut *mut void`| —    | Receives the new relay handle (out-param) |
///
/// # Returns
///
/// `0` on success. Returns `-1` if input sizes are wrong, `-5` if key material is rejected.
/// The caller must free the handle with [`opaque_relay_destroy`].
///
/// # Safety
///
/// - `private_key` must point to at least `PRIVATE_KEY_LENGTH` (32) readable bytes.
/// - `public_key` must point to at least `PUBLIC_KEY_LENGTH` (32) readable bytes.
/// - `oprf_seed_ptr` must point to at least `OPRF_SEED_LENGTH` (32) readable bytes.
/// - `handle` must be a valid, non-null pointer to a `*mut c_void` that will receive the new
///   relay handle. The caller owns the returned handle and must free it with
///   `opaque_relay_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create_with_keys(
    private_key: *const u8,
    private_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    oprf_seed_ptr: *const u8,
    oprf_seed_len: usize,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return OpaqueError::InvalidInput.to_c_int();
        }
        // SAFETY: validated above; the caller contract requires a writable out slot.
        unsafe { *handle = ptr::null_mut() };
        let handle_bytes = handle.cast::<u8>();
        let handle_size = std::mem::size_of::<*mut std::ffi::c_void>();
        if private_key.is_null()
            || private_key_len != PRIVATE_KEY_LENGTH
            || public_key.is_null()
            || public_key_len != PUBLIC_KEY_LENGTH
            || oprf_seed_ptr.is_null()
            || oprf_seed_len != OPRF_SEED_LENGTH
            || ranges_overlap(private_key, private_key_len, handle_bytes, handle_size)
            || ranges_overlap(public_key, public_key_len, handle_bytes, handle_size)
            || ranges_overlap(oprf_seed_ptr, oprf_seed_len, handle_bytes, handle_size)
        {
            return OpaqueError::InvalidInput.to_c_int();
        }

        // SAFETY: all three pointers and exact readable extents were validated above and are
        // required to remain live and disjoint from the output slot by the public contract.
        let sk = unsafe { std::slice::from_raw_parts(private_key, private_key_len) };
        let pk = unsafe { std::slice::from_raw_parts(public_key, public_key_len) };
        let seed_slice = unsafe { std::slice::from_raw_parts(oprf_seed_ptr, OPRF_SEED_LENGTH) };
        let mut oprf_seed = Zeroizing::new([0u8; OPRF_SEED_LENGTH]);
        oprf_seed.copy_from_slice(seed_slice);

        let Ok(keypair) = ResponderKeyPair::from_keys(sk, pk) else {
            return OpaqueError::InvalidInput.to_c_int();
        };
        let Ok(responder) = OpaqueResponder::new(keypair, *oprf_seed) else {
            return OpaqueError::InvalidInput.to_c_int();
        };
        let boxed = Box::new(RelayHandle {
            responder,
            in_use: AtomicBool::new(false),
        });
        inject_test_panic("relay_create_with_keys_before_publish");
        *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
        0
    }))
    .unwrap_or(FFI_PANIC)
}

/// Returns `KE2_LENGTH` (1377). Use to allocate the KE2 output buffer.
#[no_mangle]
pub extern "C" fn opaque_relay_get_ke2_length() -> usize {
    KE2_LENGTH
}

/// Returns `REGISTRATION_RECORD_LENGTH` (201). Use to validate incoming records.
#[no_mangle]
pub extern "C" fn opaque_relay_get_registration_record_length() -> usize {
    REGISTRATION_RECORD_LENGTH
}

/// Returns `RESPONDER_CREDENTIALS_LENGTH` (201). Use to allocate the credentials buffer.
#[no_mangle]
pub extern "C" fn opaque_relay_get_credentials_length() -> usize {
    RESPONDER_CREDENTIALS_LENGTH
}

/// Returns `KE1_LENGTH` (1273). Use to validate incoming KE1 buffers.
#[no_mangle]
pub extern "C" fn opaque_relay_get_ke1_length() -> usize {
    KE1_LENGTH
}

/// Returns `KE3_LENGTH` (65). Use to validate incoming KE3 buffers.
#[no_mangle]
pub extern "C" fn opaque_relay_get_ke3_length() -> usize {
    KE3_LENGTH
}

/// Returns `REGISTRATION_REQUEST_WIRE_LENGTH` (33). Expected size of incoming registration requests.
#[no_mangle]
pub extern "C" fn opaque_relay_get_registration_request_length() -> usize {
    REGISTRATION_REQUEST_WIRE_LENGTH
}

/// Returns `REGISTRATION_RESPONSE_WIRE_LENGTH` (65). Use to allocate the registration response buffer.
#[no_mangle]
pub extern "C" fn opaque_relay_get_registration_response_length() -> usize {
    REGISTRATION_RESPONSE_WIRE_LENGTH
}

/// Returns `KEM_CIPHERTEXT_LENGTH` (1088). ML-KEM-768 ciphertext size.
#[no_mangle]
pub extern "C" fn opaque_relay_get_kem_ciphertext_length() -> usize {
    pq::KEM_CIPHERTEXT_LENGTH
}

/// Returns `OPRF_SEED_LENGTH` (32). Required size for persisted relay OPRF seeds.
#[no_mangle]
pub extern "C" fn opaque_relay_get_oprf_seed_length() -> usize {
    OPRF_SEED_LENGTH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_ffi::{
        opaque_agent_create, opaque_agent_destroy, opaque_agent_generate_ke1,
        opaque_agent_generate_ke3, opaque_agent_state_create, opaque_agent_state_destroy,
    };
    use crate::{set_ffi_panic_point, take_disposal_observations};
    use opaque_core::types::is_all_zero;

    #[test]
    fn relay_constructor_panic_leaves_out_slot_null() {
        let mut keypair = std::ptr::dangling_mut::<std::ffi::c_void>();
        set_ffi_panic_point(Some("relay_keypair_generate_before_publish"));

        // SAFETY: the test-owned output slot satisfies the public contract.
        let rc = unsafe { opaque_relay_keypair_generate(&mut keypair) };

        assert_eq!(rc, FFI_PANIC);
        assert!(keypair.is_null());
    }

    #[test]
    fn remaining_relay_constructor_panics_leave_out_slots_null() {
        unsafe {
            let mut keypair = ptr::null_mut();
            assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);

            let mut relay = std::ptr::dangling_mut::<std::ffi::c_void>();
            set_ffi_panic_point(Some("relay_create_before_publish"));
            assert_eq!(opaque_relay_create(keypair, &mut relay), FFI_PANIC);
            assert!(relay.is_null());

            let mut state = std::ptr::dangling_mut::<std::ffi::c_void>();
            set_ffi_panic_point(Some("relay_state_create_before_publish"));
            assert_eq!(opaque_relay_state_create(&mut state), FFI_PANIC);
            assert!(state.is_null());

            let restored_keypair = ResponderKeyPair::generate().expect("keypair generation");
            let seed = [0x42u8; OPRF_SEED_LENGTH];
            let mut restored_relay = std::ptr::dangling_mut::<std::ffi::c_void>();
            set_ffi_panic_point(Some("relay_create_with_keys_before_publish"));
            assert_eq!(
                opaque_relay_create_with_keys(
                    restored_keypair.private_key.as_ptr(),
                    restored_keypair.private_key.len(),
                    restored_keypair.public_key.as_ptr(),
                    restored_keypair.public_key.len(),
                    seed.as_ptr(),
                    seed.len(),
                    &mut restored_relay,
                ),
                FFI_PANIC
            );
            assert!(restored_relay.is_null());

            opaque_relay_keypair_destroy(&mut keypair);
        }
    }

    #[test]
    fn relay_null_and_busy_handles_have_distinct_status_codes() {
        unsafe {
            let mut keypair = ptr::null_mut();
            assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);
            let mut sentinel = [0xA5u8; PUBLIC_KEY_LENGTH];

            // SAFETY: this unit test owns the live handle and simulates an admitted peer call.
            (*(keypair as *mut RelayKeypairHandle))
                .in_use
                .store(true, Ordering::Release);
            let busy_rc =
                opaque_relay_keypair_get_public_key(keypair, sentinel.as_mut_ptr(), sentinel.len());
            // SAFETY: this unit test owns the handle and restores it before destruction.
            (*(keypair as *mut RelayKeypairHandle))
                .in_use
                .store(false, Ordering::Release);
            let null_rc = opaque_relay_keypair_get_public_key(
                ptr::null_mut(),
                sentinel.as_mut_ptr(),
                sentinel.len(),
            );

            assert_eq!(busy_rc, FFI_BUSY);
            assert_eq!(null_rc, OpaqueError::InvalidInput.to_c_int());
            assert!(sentinel.iter().all(|byte| *byte == 0xA5));
            opaque_relay_keypair_destroy(&mut keypair);
        }
    }

    #[test]
    fn corrupted_credentials_are_rejected_before_state_admission() {
        unsafe {
            let mut keypair = ptr::null_mut();
            assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);
            let mut relay = ptr::null_mut();
            assert_eq!(opaque_relay_create(keypair, &mut relay), 0);
            let mut state = ptr::null_mut();
            assert_eq!(opaque_relay_state_create(&mut state), 0);

            let ke1 = [0u8; KE1_LENGTH];
            let credentials = [0u8; RESPONDER_CREDENTIALS_LENGTH];
            let account_id = b"alice@example.com";
            let mut sentinel = [0xA5u8; KE2_LENGTH];
            let rc = opaque_relay_generate_ke2(
                relay,
                ke1.as_ptr(),
                ke1.len(),
                account_id.as_ptr(),
                account_id.len(),
                credentials.as_ptr(),
                credentials.len(),
                sentinel.as_mut_ptr(),
                sentinel.len(),
                state,
            );

            assert_eq!(rc, FFI_CORRUPTED_RECORD);
            assert!(sentinel.iter().all(|byte| *byte == 0xA5));
            let state_ref = &*(state as *const RelayStateHandle);
            assert_eq!(state_ref.state.phase, opaque_relay::ResponderPhase::Created);
            opaque_relay_state_destroy(&mut state);
            opaque_relay_destroy(&mut relay);
            opaque_relay_keypair_destroy(&mut keypair);
        }
    }

    #[test]
    fn caught_relay_panic_terminalizes_state_and_preserves_output() {
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
            let mut agent_state = ptr::null_mut();
            assert_eq!(opaque_agent_state_create(&mut agent_state), 0);
            let password = b"correct horse battery staple";
            let account_id = b"alice@example.com";
            let mut ke1 = [0u8; KE1_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke1(
                    agent,
                    password.as_ptr(),
                    password.len(),
                    account_id.as_ptr(),
                    account_id.len(),
                    agent_state,
                    ke1.as_mut_ptr(),
                    ke1.len(),
                ),
                0
            );

            let mut relay_state = ptr::null_mut();
            assert_eq!(opaque_relay_state_create(&mut relay_state), 0);
            let mut sentinel = [0xA5u8; KE2_LENGTH];
            set_ffi_panic_point(Some("relay_generate_ke2_before_commit"));
            let rc = opaque_relay_generate_ke2(
                relay,
                ke1.as_ptr(),
                ke1.len(),
                account_id.as_ptr(),
                account_id.len(),
                ptr::null(),
                0,
                sentinel.as_mut_ptr(),
                sentinel.len(),
                relay_state,
            );

            assert_eq!(rc, FFI_PANIC);
            assert!(sentinel.iter().all(|byte| *byte == 0xA5));
            let state_ref = &*(relay_state as *const RelayStateHandle);
            assert_eq!(
                state_ref.state.phase,
                opaque_relay::ResponderPhase::Finished
            );
            assert!(is_all_zero(state_ref.state.responder_private_key()));
            assert!(is_all_zero(
                state_ref.state.responder_ephemeral_private_key()
            ));
            assert!(is_all_zero(state_ref.state.session_key()));

            opaque_agent_state_destroy(&mut agent_state);
            opaque_agent_destroy(&mut agent);
            opaque_relay_state_destroy(&mut relay_state);
            opaque_relay_destroy(&mut relay);
            opaque_relay_keypair_destroy(&mut keypair);
        }
    }

    #[test]
    fn destroy_observes_zeroized_populated_relay_storage() {
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
            let mut agent_state = ptr::null_mut();
            assert_eq!(opaque_agent_state_create(&mut agent_state), 0);
            let password = b"correct horse battery staple";
            let account_id = b"alice@example.com";
            let mut ke1 = [0u8; KE1_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke1(
                    agent,
                    password.as_ptr(),
                    password.len(),
                    account_id.as_ptr(),
                    account_id.len(),
                    agent_state,
                    ke1.as_mut_ptr(),
                    ke1.len(),
                ),
                0
            );

            let mut relay_state = ptr::null_mut();
            assert_eq!(opaque_relay_state_create(&mut relay_state), 0);
            let mut ke2 = [0u8; KE2_LENGTH];
            assert_eq!(
                opaque_relay_generate_ke2(
                    relay,
                    ke1.as_ptr(),
                    ke1.len(),
                    account_id.as_ptr(),
                    account_id.len(),
                    ptr::null(),
                    0,
                    ke2.as_mut_ptr(),
                    ke2.len(),
                    relay_state,
                ),
                0
            );
            let state_ref = &*(relay_state as *const RelayStateHandle);
            assert!(!is_all_zero(state_ref.state.responder_private_key()));
            assert!(!is_all_zero(state_ref.state.session_key()));

            opaque_agent_state_destroy(&mut agent_state);
            opaque_agent_destroy(&mut agent);
            take_disposal_observations();

            opaque_relay_state_destroy(&mut relay_state);
            opaque_relay_destroy(&mut relay);
            opaque_relay_keypair_destroy(&mut keypair);
            let observations = take_disposal_observations();

            for object in ["RelayStateHandle", "RelayHandle", "RelayKeypairHandle"] {
                let observation = observations
                    .iter()
                    .find(|item| item.object == object)
                    .unwrap_or_else(|| panic!("missing disposal observation for {object}"));
                assert!(observation.fields.iter().all(|(_, erased)| *erased));
            }
        }
    }

    #[test]
    fn ffi_unknown_user_returns_fake_ke2() {
        unsafe {
            let mut keypair_handle: *mut std::ffi::c_void = ptr::null_mut();
            assert_eq!(opaque_relay_keypair_generate(&mut keypair_handle), 0);

            let mut relay_public_key = [0u8; PUBLIC_KEY_LENGTH];
            assert_eq!(
                opaque_relay_keypair_get_public_key(
                    keypair_handle,
                    relay_public_key.as_mut_ptr(),
                    relay_public_key.len(),
                ),
                0
            );

            let mut relay_handle: *mut std::ffi::c_void = ptr::null_mut();
            assert_eq!(opaque_relay_create(keypair_handle, &mut relay_handle), 0);

            let mut agent_handle: *mut std::ffi::c_void = ptr::null_mut();
            assert_eq!(
                opaque_agent_create(
                    relay_public_key.as_ptr(),
                    relay_public_key.len(),
                    &mut agent_handle,
                ),
                0
            );

            let mut agent_state: *mut std::ffi::c_void = ptr::null_mut();
            assert_eq!(opaque_agent_state_create(&mut agent_state), 0);

            let password = b"correct horse battery staple";
            let account_id = b"ghost@example.com";
            let mut ke1 = vec![0u8; KE1_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke1(
                    agent_handle,
                    password.as_ptr(),
                    password.len(),
                    account_id.as_ptr(),
                    account_id.len(),
                    agent_state,
                    ke1.as_mut_ptr(),
                    ke1.len(),
                ),
                0
            );

            let mut relay_state: *mut std::ffi::c_void = ptr::null_mut();
            assert_eq!(opaque_relay_state_create(&mut relay_state), 0);

            let mut ke2 = vec![0u8; KE2_LENGTH];
            assert_eq!(
                opaque_relay_generate_ke2(
                    relay_handle,
                    ke1.as_ptr(),
                    ke1.len(),
                    account_id.as_ptr(),
                    account_id.len(),
                    ptr::null(),
                    0,
                    ke2.as_mut_ptr(),
                    ke2.len(),
                    relay_state,
                ),
                0
            );

            let mut ke3 = vec![0u8; KE3_LENGTH];
            assert_eq!(
                opaque_agent_generate_ke3(
                    agent_handle,
                    ke2.as_ptr(),
                    ke2.len(),
                    agent_state,
                    ke3.as_mut_ptr(),
                    ke3.len(),
                ),
                -5
            );

            opaque_agent_state_destroy(&mut agent_state);
            opaque_agent_destroy(&mut agent_handle);
            opaque_relay_state_destroy(&mut relay_state);
            opaque_relay_destroy(&mut relay_handle);
            opaque_relay_keypair_destroy(&mut keypair_handle);
        }
    }
}
