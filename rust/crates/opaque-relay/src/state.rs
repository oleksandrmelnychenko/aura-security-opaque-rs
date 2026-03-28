// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

use opaque_core::oprf::{InMemoryEvaluator, OprfEvaluator};
use opaque_core::types::{
    constant_time_eq, pq, OpaqueError, OpaqueResult, CREDENTIAL_RESPONSE_LENGTH, ENVELOPE_LENGTH,
    HASH_LENGTH, MAC_LENGTH, MASTER_KEY_LENGTH, NONCE_LENGTH, OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, REGISTRATION_RESPONSE_LENGTH, STATE_MAX_LIFETIME_SECS,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderPhase {
    Created,

    Ke2Generated,

    Finished,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderState {
    #[zeroize(skip)]
    pub phase: ResponderPhase,

    #[zeroize(skip)]
    created_at: Instant,

    pub responder_private_key: [u8; PRIVATE_KEY_LENGTH],

    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub responder_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],

    pub responder_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub session_key: [u8; HASH_LENGTH],

    pub expected_initiator_mac: [u8; MAC_LENGTH],

    pub master_key: [u8; MASTER_KEY_LENGTH],

    #[zeroize(skip)]
    pub handshake_complete: bool,

    pub pq_shared_secret: [u8; pq::KEM_SHARED_SECRET_LENGTH],
}

impl ResponderState {
    pub fn is_expired(&self) -> bool {
        Instant::now()
            .checked_duration_since(self.created_at)
            .is_none_or(|d| d.as_secs() >= STATE_MAX_LIFETIME_SECS)
    }

    pub fn invalidate(&mut self) {
        self.zeroize();
        self.phase = ResponderPhase::Finished;
        self.handshake_complete = false;
    }

    #[cfg(test)]
    pub(crate) fn expire_for_test(&mut self) {
        self.created_at = Instant::now() - Duration::from_secs(STATE_MAX_LIFETIME_SECS + 1);
    }

    pub fn new() -> Self {
        Self {
            phase: ResponderPhase::Created,
            created_at: Instant::now(),
            responder_private_key: [0u8; PRIVATE_KEY_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            responder_ephemeral_private_key: [0u8; PRIVATE_KEY_LENGTH],
            responder_ephemeral_public_key: [0u8; PUBLIC_KEY_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            session_key: [0u8; HASH_LENGTH],
            expected_initiator_mac: [0u8; MAC_LENGTH],
            master_key: [0u8; MASTER_KEY_LENGTH],
            handshake_complete: false,
            pq_shared_secret: [0u8; pq::KEM_SHARED_SECRET_LENGTH],
        }
    }
}

impl Default for ResponderState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponderKeyPair {
    pub private_key: [u8; PRIVATE_KEY_LENGTH],

    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ResponderKeyPair {
    pub fn generate() -> OpaqueResult<Self> {
        let private_key = opaque_core::crypto::random_nonzero_scalar()?;
        let public_key = opaque_core::crypto::scalarmult_base(&private_key)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_keys(private_key: &[u8], public_key: &[u8]) -> OpaqueResult<Self> {
        if private_key.len() != PRIVATE_KEY_LENGTH || public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(OpaqueError::InvalidInput);
        }
        opaque_core::crypto::validate_public_key(public_key)?;

        let sk: &[u8; PRIVATE_KEY_LENGTH] = private_key
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput)?;
        let derived = opaque_core::crypto::scalarmult_base(sk)?;
        if !constant_time_eq(public_key, &derived) {
            return Err(OpaqueError::InvalidPublicKey);
        }

        let mut kp = Self {
            private_key: [0u8; PRIVATE_KEY_LENGTH],
            public_key: [0u8; PUBLIC_KEY_LENGTH],
        };
        kp.private_key.copy_from_slice(private_key);
        kp.public_key.copy_from_slice(public_key);
        Ok(kp)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationResponse {
    pub data: [u8; REGISTRATION_RESPONSE_LENGTH],
}

impl RegistrationResponse {
    pub fn new() -> Self {
        Self {
            data: [0u8; REGISTRATION_RESPONSE_LENGTH],
        }
    }
}

impl Default for RegistrationResponse {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke2Message {
    pub responder_nonce: [u8; NONCE_LENGTH],

    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],

    pub credential_response: [u8; CREDENTIAL_RESPONSE_LENGTH],

    pub responder_mac: [u8; MAC_LENGTH],

    pub kem_ciphertext: [u8; pq::KEM_CIPHERTEXT_LENGTH],
}

impl Ke2Message {
    pub fn new() -> Self {
        Self {
            responder_nonce: [0u8; NONCE_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            credential_response: [0u8; CREDENTIAL_RESPONSE_LENGTH],
            responder_mac: [0u8; MAC_LENGTH],
            kem_ciphertext: [0u8; pq::KEM_CIPHERTEXT_LENGTH],
        }
    }
}

impl Default for Ke2Message {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderCredentials {
    pub envelope: Vec<u8>,

    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],

    #[zeroize(skip)]
    pub registered: bool,
}

impl ResponderCredentials {
    pub fn new() -> Self {
        Self {
            envelope: vec![0u8; ENVELOPE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            registered: false,
        }
    }
}

impl Default for ResponderCredentials {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OpaqueResponder {
    keypair: ResponderKeyPair,
    evaluator: Box<dyn OprfEvaluator>,
}

impl Zeroize for OpaqueResponder {
    fn zeroize(&mut self) {
        self.keypair.zeroize();
        self.evaluator.zeroize_secret();
    }
}

impl Drop for OpaqueResponder {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl OpaqueResponder {
    pub fn new(keypair: ResponderKeyPair, oprf_seed: [u8; OPRF_SEED_LENGTH]) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(&keypair.public_key)?;
        let evaluator = InMemoryEvaluator::new(oprf_seed)?;
        Ok(Self {
            keypair,
            evaluator: Box::new(evaluator),
        })
    }

    pub fn with_evaluator(
        keypair: ResponderKeyPair,
        evaluator: Box<dyn OprfEvaluator>,
    ) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(&keypair.public_key)?;
        Ok(Self { keypair, evaluator })
    }

    pub fn generate() -> OpaqueResult<Self> {
        let keypair = ResponderKeyPair::generate()?;
        let mut oprf_seed = [0u8; OPRF_SEED_LENGTH];
        opaque_core::crypto::random_bytes(&mut oprf_seed)?;
        let evaluator = InMemoryEvaluator::new(oprf_seed)?;
        oprf_seed.zeroize();
        Ok(Self {
            keypair,
            evaluator: Box::new(evaluator),
        })
    }

    pub fn keypair(&self) -> &ResponderKeyPair {
        &self.keypair
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.keypair.public_key
    }

    pub fn evaluator(&self) -> &dyn OprfEvaluator {
        &*self.evaluator
    }
}
