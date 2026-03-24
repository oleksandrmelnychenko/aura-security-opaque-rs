// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROTOCOL_VERSION_1: u8 = 0x01;

pub const PROTOCOL_VERSION: u8 = PROTOCOL_VERSION_1;

pub const VERSION_PREFIX_LENGTH: usize = 1;

pub const OPRF_SEED_LENGTH: usize = 32;

pub const PRIVATE_KEY_LENGTH: usize = 32;

pub const PUBLIC_KEY_LENGTH: usize = 32;

pub const MASTER_KEY_LENGTH: usize = 32;

pub const NONCE_LENGTH: usize = 24;

pub const MAC_LENGTH: usize = 64;

pub const HASH_LENGTH: usize = 64;

pub const ENVELOPE_LENGTH: usize = 136;

pub const REGISTRATION_REQUEST_LENGTH: usize = 32;

pub const REGISTRATION_RESPONSE_LENGTH: usize = 64;

pub const CREDENTIAL_REQUEST_LENGTH: usize = REGISTRATION_REQUEST_LENGTH;

pub const REGISTRATION_REQUEST_WIRE_LENGTH: usize =
    VERSION_PREFIX_LENGTH + REGISTRATION_REQUEST_LENGTH;

pub const REGISTRATION_RESPONSE_WIRE_LENGTH: usize =
    VERSION_PREFIX_LENGTH + REGISTRATION_RESPONSE_LENGTH;

pub const CREDENTIAL_RESPONSE_LENGTH: usize = 168;

pub const MAX_SECURE_KEY_LENGTH: usize = 4096;

pub const DH_COMPONENT_COUNT: usize = 4;

pub const CLASSICAL_IKM_LENGTH: usize = DH_COMPONENT_COUNT * PUBLIC_KEY_LENGTH;

pub const STATE_MAX_LIFETIME_SECS: u64 = 300;

pub const KE1_BASE_LENGTH: usize = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;

pub const KE2_BASE_LENGTH: usize =
    NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH;

pub mod pq {

    pub const KEM_PUBLIC_KEY_LENGTH: usize = 1184;

    pub const KEM_SECRET_KEY_LENGTH: usize = 2400;

    pub const KEM_CIPHERTEXT_LENGTH: usize = 1088;

    pub const KEM_SHARED_SECRET_LENGTH: usize = 32;

    pub const COMBINED_IKM_LENGTH: usize = super::CLASSICAL_IKM_LENGTH + KEM_SHARED_SECRET_LENGTH;
}

pub const KE1_PAYLOAD_LENGTH: usize = KE1_BASE_LENGTH + pq::KEM_PUBLIC_KEY_LENGTH;

pub const KE2_PAYLOAD_LENGTH: usize = KE2_BASE_LENGTH + pq::KEM_CIPHERTEXT_LENGTH;

pub const REGISTRATION_RECORD_PAYLOAD_LENGTH: usize = ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH;

pub const KE1_LENGTH: usize = VERSION_PREFIX_LENGTH + KE1_PAYLOAD_LENGTH;

pub const KE2_LENGTH: usize = VERSION_PREFIX_LENGTH + KE2_PAYLOAD_LENGTH;

pub const KE3_LENGTH: usize = VERSION_PREFIX_LENGTH + MAC_LENGTH;

pub const REGISTRATION_RECORD_LENGTH: usize =
    VERSION_PREFIX_LENGTH + REGISTRATION_RECORD_PAYLOAD_LENGTH;

pub const RESPONDER_CREDENTIALS_LENGTH: usize = REGISTRATION_RECORD_LENGTH;

const _: () = assert!(PRIVATE_KEY_LENGTH == PUBLIC_KEY_LENGTH);
const _: () = assert!(PRIVATE_KEY_LENGTH == 32);
const _: () = assert!(NONCE_LENGTH == 24);
const _: () = assert!(MAC_LENGTH == 64);
const _: () = assert!(CREDENTIAL_REQUEST_LENGTH == REGISTRATION_REQUEST_LENGTH);
const _: () = assert!(CREDENTIAL_RESPONSE_LENGTH == PUBLIC_KEY_LENGTH + ENVELOPE_LENGTH);
const _: () = assert!(KE1_BASE_LENGTH == 88);
const _: () = assert!(KE2_BASE_LENGTH == 288);
const _: () = assert!(REGISTRATION_RECORD_PAYLOAD_LENGTH == 168);
const _: () = assert!(KE1_PAYLOAD_LENGTH == 1272);
const _: () = assert!(KE2_PAYLOAD_LENGTH == 1376);
const _: () = assert!(KE1_LENGTH == 1273);
const _: () = assert!(KE2_LENGTH == 1377);
const _: () = assert!(KE3_LENGTH == 65);
const _: () = assert!(REGISTRATION_RECORD_LENGTH == 169);

pub const SECRETBOX_KEY_LENGTH: usize = 32;

pub const SECRETBOX_MAC_LENGTH: usize = 16;

pub mod labels {

    pub const OPRF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF";

    pub const OPRF_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Key";

    pub const OPRF_SEED_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Seed";

    pub const ENVELOPE_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/EnvelopeKey";

    pub const HKDF_SALT: &[u8] = b"ECLIPTIX-OPAQUE-v1/HKDF-Salt";

    pub const TRANSCRIPT_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/Transcript";

    pub const ACCOUNT_CONTEXT_BINDING: &[u8] = b"ECLIPTIX-OPAQUE-v2/AccountContext";

    pub const KSF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF";

    pub const KSF_SALT_LABEL: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF-Salt";

    pub const SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/SessionKey";

    pub const MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/MasterKey";

    pub const RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/ResponderMAC";

    pub const INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/InitiatorMAC";

    pub const DERIVE_KEYPAIR_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/DeriveKeyPair";

    pub const FAKE_CREDENTIALS_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/FakeCredentials";
}

pub mod pq_labels {

    pub const PQ_COMBINER_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/Combiner";

    pub const PQ_KEM_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/KEM";

    pub const PQ_SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/SessionKey";

    pub const PQ_MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/MasterKey";

    pub const PQ_RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC";

    pub const PQ_INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC";
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueError {
    #[error("invalid input parameter")]
    InvalidInput,

    #[error("cryptographic operation failed")]
    CryptoError,

    #[error("protocol message has invalid format or length")]
    InvalidProtocolMessage,

    #[error("validation failed")]
    ValidationError,

    #[error("authentication failed")]
    AuthenticationError,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("account already registered")]
    AlreadyRegistered,

    #[error("malformed ML-KEM key or ciphertext")]
    InvalidKemInput,

    #[error("envelope has invalid format")]
    InvalidEnvelope,

    #[error("unsupported protocol version")]
    UnsupportedVersion,
}

impl OpaqueError {
    /// FFI-safe return code mapping.
    ///
    /// SECURITY: protocol/authentication-stage failures are intentionally collapsed
    /// into a single `-5` code to reduce account-enumeration and stage-fingerprinting
    /// signals for remote callers.
    pub fn to_c_int(self) -> i32 {
        match self {
            OpaqueError::InvalidInput => -1,
            OpaqueError::CryptoError => -2,
            OpaqueError::InvalidProtocolMessage => -5,
            OpaqueError::ValidationError => -5,
            OpaqueError::AuthenticationError => -5,
            OpaqueError::InvalidPublicKey => -6,
            OpaqueError::AlreadyRegistered => -7,
            OpaqueError::InvalidKemInput => -5,
            OpaqueError::InvalidEnvelope => -5,
            OpaqueError::UnsupportedVersion => -5,
        }
    }
}

pub type OpaqueResult<T> = Result<T, OpaqueError>;

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resize(&mut self, new_len: usize) {
        if new_len < self.0.len() {
            self.0[new_len..].zeroize();
        }
        self.0.resize(new_len, 0);
    }
}

impl std::ops::Deref for SecureBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {}])", self.0.len())
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Envelope {
    pub nonce: Vec<u8>,

    pub ciphertext: Vec<u8>,

    pub auth_tag: Vec<u8>,
}

impl Envelope {
    pub fn new() -> Self {
        Self {
            nonce: vec![0u8; NONCE_LENGTH],
            ciphertext: Vec::new(),
            auth_tag: vec![0u8; SECRETBOX_MAC_LENGTH],
        }
    }
}

impl Default for Envelope {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::{Choice, ConstantTimeEq};
    let len_eq: Choice = (a.len() as u64).ct_eq(&(b.len() as u64));
    let content_eq: Choice = if a.len() == b.len() {
        a.ct_eq(b)
    } else {
        Choice::from(0)
    };
    (len_eq & content_eq).into()
}

#[inline]
pub fn is_all_zero(data: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let mut acc = 0u8;
    for &b in data {
        acc |= b;
    }
    acc.ct_eq(&0u8).into()
}

#[inline]
pub fn ct_select_bytes(out: &mut [u8], a: &[u8], b: &[u8], choice: subtle::Choice) {
    use subtle::ConditionallySelectable;
    assert_eq!(out.len(), a.len());
    assert_eq!(out.len(), b.len());
    for i in 0..out.len() {
        out[i] = u8::conditional_select(&b[i], &a[i], choice);
    }
}
