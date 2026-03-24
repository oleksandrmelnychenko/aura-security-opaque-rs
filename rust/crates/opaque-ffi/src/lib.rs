// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Ecliptix OPAQUE FFI
//!
//! C-compatible Foreign Function Interface for the Ecliptix hybrid post-quantum OPAQUE protocol.
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

use opaque_core::types::{OpaqueError, OpaqueResult};

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
