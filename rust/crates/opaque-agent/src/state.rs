// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

use opaque_core::types::{
    pq, OpaqueResult, ENVELOPE_LENGTH, HASH_LENGTH, MAC_LENGTH, MASTER_KEY_LENGTH,
    MAX_SECURE_KEY_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    REGISTRATION_REQUEST_LENGTH, STATE_MAX_LIFETIME_SECS,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorPhase {
    Created,

    RegistrationRequested,

    RegistrationFinalized,

    Ke1Generated,

    Ke3Generated,

    Finished,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorState {
    #[zeroize(skip)]
    pub phase: InitiatorPhase,

    #[zeroize(skip)]
    created_at: Instant,

    pub(crate) secure_key: [u8; MAX_SECURE_KEY_LENGTH],

    pub(crate) secure_key_len: usize,

    pub(crate) initiator_private_key: [u8; PRIVATE_KEY_LENGTH],

    pub(crate) initiator_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub(crate) initiator_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],

    pub(crate) initiator_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub(crate) responder_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub(crate) session_key: [u8; HASH_LENGTH],

    pub(crate) oblivious_prf_blind_scalar: [u8; PRIVATE_KEY_LENGTH],

    pub(crate) initiator_nonce: [u8; NONCE_LENGTH],

    pub(crate) account_context_hash: [u8; HASH_LENGTH],

    pub(crate) master_key: [u8; MASTER_KEY_LENGTH],

    pub(crate) pq_ephemeral_public_key: [u8; pq::KEM_PUBLIC_KEY_LENGTH],

    pub(crate) pq_ephemeral_secret_key: [u8; pq::KEM_SECRET_KEY_LENGTH],

    pub(crate) pq_shared_secret: [u8; pq::KEM_SHARED_SECRET_LENGTH],
}

impl InitiatorState {
    pub fn is_expired(&self) -> bool {
        if matches!(
            self.phase,
            InitiatorPhase::Created
                | InitiatorPhase::RegistrationFinalized
                | InitiatorPhase::Finished
        ) {
            return false;
        }
        Instant::now()
            .checked_duration_since(self.created_at)
            .is_none_or(|d| d.as_secs() >= STATE_MAX_LIFETIME_SECS)
    }

    pub(crate) fn refresh_deadline(&mut self) {
        self.created_at = Instant::now();
    }

    pub fn initiator_private_key(&self) -> &[u8; PRIVATE_KEY_LENGTH] {
        &self.initiator_private_key
    }

    pub fn initiator_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.initiator_public_key
    }

    pub fn initiator_ephemeral_private_key(&self) -> &[u8; PRIVATE_KEY_LENGTH] {
        &self.initiator_ephemeral_private_key
    }

    pub fn initiator_ephemeral_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.initiator_ephemeral_public_key
    }

    pub fn initiator_nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.initiator_nonce
    }

    pub fn pq_ephemeral_public_key(&self) -> &[u8; pq::KEM_PUBLIC_KEY_LENGTH] {
        &self.pq_ephemeral_public_key
    }

    pub fn pq_ephemeral_secret_key(&self) -> &[u8; pq::KEM_SECRET_KEY_LENGTH] {
        &self.pq_ephemeral_secret_key
    }

    pub fn pq_shared_secret(&self) -> &[u8; pq::KEM_SHARED_SECRET_LENGTH] {
        &self.pq_shared_secret
    }

    pub fn invalidate(&mut self) {
        self.zeroize();
        self.phase = InitiatorPhase::Finished;
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.created_at = Instant::now() - Duration::from_secs(STATE_MAX_LIFETIME_SECS + 1);
    }

    pub fn new() -> Self {
        Self {
            phase: InitiatorPhase::Created,
            created_at: Instant::now(),
            secure_key: [0u8; MAX_SECURE_KEY_LENGTH],
            secure_key_len: 0,
            initiator_private_key: [0u8; PRIVATE_KEY_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            initiator_ephemeral_private_key: [0u8; PRIVATE_KEY_LENGTH],
            initiator_ephemeral_public_key: [0u8; PUBLIC_KEY_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            session_key: [0u8; HASH_LENGTH],
            oblivious_prf_blind_scalar: [0u8; PRIVATE_KEY_LENGTH],
            initiator_nonce: [0u8; NONCE_LENGTH],
            account_context_hash: [0u8; HASH_LENGTH],
            master_key: [0u8; MASTER_KEY_LENGTH],
            pq_ephemeral_public_key: [0u8; pq::KEM_PUBLIC_KEY_LENGTH],
            pq_ephemeral_secret_key: [0u8; pq::KEM_SECRET_KEY_LENGTH],
            pq_shared_secret: [0u8; pq::KEM_SHARED_SECRET_LENGTH],
        }
    }
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRequest {
    pub data: [u8; REGISTRATION_REQUEST_LENGTH],
}

impl RegistrationRequest {
    pub fn new() -> Self {
        Self {
            data: [0u8; REGISTRATION_REQUEST_LENGTH],
        }
    }
}

impl Default for RegistrationRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRecord {
    pub envelope: Vec<u8>,

    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl RegistrationRecord {
    pub fn new() -> Self {
        Self {
            envelope: vec![0u8; ENVELOPE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
        }
    }
}

impl Default for RegistrationRecord {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke1Message {
    pub initiator_nonce: [u8; NONCE_LENGTH],

    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub credential_request: [u8; REGISTRATION_REQUEST_LENGTH],

    pub pq_ephemeral_public_key: [u8; pq::KEM_PUBLIC_KEY_LENGTH],
}

impl Ke1Message {
    pub fn new() -> Self {
        Self {
            initiator_nonce: [0u8; NONCE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            credential_request: [0u8; REGISTRATION_REQUEST_LENGTH],
            pq_ephemeral_public_key: [0u8; pq::KEM_PUBLIC_KEY_LENGTH],
        }
    }
}

impl Default for Ke1Message {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke3Message {
    pub initiator_mac: [u8; MAC_LENGTH],
}

impl Ke3Message {
    pub fn new() -> Self {
        Self {
            initiator_mac: [0u8; MAC_LENGTH],
        }
    }
}

impl Default for Ke3Message {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpaqueInitiator {
    responder_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl OpaqueInitiator {
    pub fn new(responder_public_key: &[u8]) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(responder_public_key)?;
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(responder_public_key);
        Ok(Self {
            responder_public_key: key,
        })
    }

    pub fn responder_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.responder_public_key
    }
}
