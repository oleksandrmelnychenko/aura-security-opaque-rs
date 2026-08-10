// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Aura OPAQUE FFI
//!
//! C-compatible Foreign Function Interface for the Aura hybrid post-quantum OPAQUE protocol.
//! This crate exposes the agent (client) and relay (server) APIs as `extern "C"` functions
//! suitable for consumption from Swift, Kotlin, C, or any language with C FFI support.
//!
//! ## Wire sizes (bytes)
//!
//! | Constant                       | Value |
//! |--------------------------------|------:|
//! | `PUBLIC_KEY_LENGTH`            |    32 |
//! | `PRIVATE_KEY_LENGTH`           |    32 |
//! | `OPRF_SEED_LENGTH`             |    32 |
//! | `REGISTRATION_REQUEST_WIRE_LENGTH`  |    33 |
//! | `REGISTRATION_RESPONSE_WIRE_LENGTH` |    65 |
//! | `REGISTRATION_RECORD_LENGTH`   |   201 |
//! | `KE1_LENGTH`                   |  1273 |
//! | `KE2_LENGTH`                   |  1377 |
//! | `KE3_LENGTH`                   |    65 |
//! | `HASH_LENGTH` (session key)    |    64 |
//! | `EXPORT_KEY_LENGTH`            |    32 |
//!
//! ## Return codes
//!
//! Every function returns `i32`. Zero means success; negative values are errors:
//!
//! | Code  | Meaning                                    |
//! |------:|--------------------------------------------|
//! |   `0` | Success                                    |
//! |  `-1` | Invalid input parameter                    |
//! |  `-2` | Cryptographic operation failed             |
//! |  `-3` | Invalid protocol message format or length  |
//! |  `-4` | Validation failed                          |
//! |  `-5` | Authentication/protocol validation failed  |
//! |  `-6` | Invalid public key                         |
//! |  `-7` | Account already registered                 |
//! |  `-8` | Malformed ML-KEM key or ciphertext         |
//! |  `-9` | Envelope has invalid format                |
//! | `-10` | Unsupported protocol version               |
//! |`-101` | Provided credentials record is malformed   |
//! | `-99` | Internal panic (should never happen)        |
//! |`-100` | Handle is busy (concurrent call rejected)  |
//!
//! Protocol-stage validation failures are intentionally collapsed to `-5` in
//! current FFI paths; the distinct public codes remain part of the ABI.
//!
//! ## Thread safety
//!
//! Each handle carries an atomic busy flag. A second call on the same handle while the first
//! is still running returns `-100` (`FFI_BUSY`). Different handles can be used concurrently.
//! Handle destruction requires external lifetime synchronization: a destroy call must not
//! overlap an operation through the same handle or through a copied alias.

mod agent_ffi;
mod relay_ffi;

use std::ffi::c_char;

use opaque_core::types::OpaqueError;

static VERSION_STRING: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

pub(crate) fn ffi_error_to_int(error: OpaqueError) -> i32 {
    error.to_c_int()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HandleAccessError {
    InvalidHandle,
    Busy,
}

pub(crate) fn handle_access_to_int(error: HandleAccessError) -> i32 {
    match error {
        HandleAccessError::InvalidHandle => OpaqueError::InvalidInput.to_c_int(),
        HandleAccessError::Busy => -100,
    }
}

/// Returns true when two non-empty byte ranges overlap or either end address overflows.
///
/// This is a public-argument validation aid, not a pointer-validity oracle. Callers must still
/// supply live allocations with the documented extents.
pub(crate) fn ranges_overlap(
    left: *const u8,
    left_len: usize,
    right: *const u8,
    right_len: usize,
) -> bool {
    if left_len == 0 || right_len == 0 {
        return false;
    }

    let left_start = left.addr();
    let right_start = right.addr();
    let Some(left_end) = left_start.checked_add(left_len) else {
        return true;
    };
    let Some(right_end) = right_start.checked_add(right_len) else {
        return true;
    };

    left_start < right_end && right_start < left_end
}

#[cfg(test)]
thread_local! {
    static FFI_PANIC_POINT: std::cell::Cell<Option<&'static str>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn set_ffi_panic_point(point: Option<&'static str>) {
    FFI_PANIC_POINT.with(|slot| slot.set(point));
}

#[cfg(test)]
pub(crate) fn inject_test_panic(point: &'static str) {
    FFI_PANIC_POINT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            panic!("injected FFI panic at {point}");
        }
    });
}

#[cfg(not(test))]
#[inline(always)]
pub(crate) fn inject_test_panic(_: &'static str) {}

#[no_mangle]
pub extern "C" fn opaque_version() -> *const c_char {
    VERSION_STRING.as_ptr().cast()
}

#[no_mangle]
pub extern "C" fn opaque_shutdown() {}

#[no_mangle]
pub extern "C" fn opaque_error_string(code: i32) -> *const c_char {
    match code {
        0 => c"success".as_ptr(),
        -1 => c"invalid input parameter".as_ptr(),
        -2 => c"cryptographic operation failed".as_ptr(),
        -3 => c"protocol message has invalid format or length".as_ptr(),
        -4 => c"validation failed".as_ptr(),
        -5 => c"authentication or protocol validation failed".as_ptr(),
        -6 => c"invalid public key".as_ptr(),
        -7 => c"account already registered".as_ptr(),
        -8 => c"malformed ML-KEM key or ciphertext".as_ptr(),
        -9 => c"envelope has invalid format".as_ptr(),
        -10 => c"unsupported protocol version".as_ptr(),
        -99 => c"internal FFI panic".as_ptr(),
        -100 => c"handle is busy".as_ptr(),
        -101 => c"provided credentials record is malformed".as_ptr(),
        _ => c"unknown error".as_ptr(),
    }
}
