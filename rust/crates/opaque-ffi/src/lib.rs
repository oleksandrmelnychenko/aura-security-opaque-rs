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
//! | `REGISTRATION_RECORD_LENGTH`   |   169 |
//! | `KE1_LENGTH`                   |  1273 |
//! | `KE2_LENGTH`                   |  1377 |
//! | `KE3_LENGTH`                   |    65 |
//! | `HASH_LENGTH` (session key)    |    64 |
//! | `MASTER_KEY_LENGTH`            |    32 |
//!
//! ## Return codes
//!
//! Every function returns `i32`. Zero means success; negative values are errors:
//!
//! | Code  | Meaning                                    |
//! |------:|--------------------------------------------|
//! |   `0` | Success                                    |
//! |  `-1` | Invalid input parameter                    |
//! |  `-5` | Authentication/protocol validation failed  |
//! |  `-7` | Account already registered                 |
//! |`-101` | Provided credentials record is malformed   |
//! | `-99` | Internal panic (should never happen)        |
//! |`-100` | Handle is busy (concurrent call rejected)  |
//!
//! ## Thread safety
//!
//! Each handle carries an atomic busy flag. A second call on the same handle while the first
//! is still running returns `-100` (`FFI_BUSY`). Different handles can be used concurrently.

mod agent_ffi;
mod relay_ffi;

use std::ffi::c_char;

use opaque_core::types::{OpaqueError, OpaqueResult};

static VERSION_STRING: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

pub(crate) fn ffi_error_to_int(error: OpaqueError) -> i32 {
    match error {
        OpaqueError::InvalidInput => -1,
        OpaqueError::AlreadyRegistered => -7,
        _ => -5,
    }
}

pub(crate) fn result_to_int(r: OpaqueResult<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => ffi_error_to_int(e),
    }
}

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
