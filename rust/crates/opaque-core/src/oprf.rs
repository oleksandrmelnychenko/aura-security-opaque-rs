// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::crypto;
use crate::types::{
    labels, OpaqueError, OpaqueResult, HASH_LENGTH, OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH,
};
use labels::FAKE_CREDENTIALS_CONTEXT;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HASH_TO_GROUP_DOMAIN: u8 = 0x00;

const FINALIZE_DOMAIN: u8 = 0x01;

pub fn hash_to_group(input: &[u8], point_out: &mut [u8; PUBLIC_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::OPRF_CONTEXT, &[HASH_TO_GROUP_DOMAIN], input],
        &mut hash,
    );

    let mut point = curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&hash);
    point_out.copy_from_slice(point.compress().as_bytes());
    point.zeroize();

    hash.zeroize();
    Ok(())
}

pub fn blind(
    input: &[u8],
    blinded_element: &mut [u8; PUBLIC_KEY_LENGTH],
    blind_scalar: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    *blind_scalar = crypto::random_nonzero_scalar()?;

    let mut element = [0u8; PUBLIC_KEY_LENGTH];
    hash_to_group(input, &mut element)?;

    let result = crypto::scalar_mult(blind_scalar, &element, blinded_element);
    element.zeroize();
    result
}

pub fn evaluate(
    blinded_element: &[u8; PUBLIC_KEY_LENGTH],
    private_key: &[u8; PRIVATE_KEY_LENGTH],
    evaluated_element: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    crypto::scalar_mult(private_key, blinded_element, evaluated_element)
}

pub fn finalize(
    input: &[u8],
    blind_scalar: &[u8; PRIVATE_KEY_LENGTH],
    evaluated_element: &[u8; PUBLIC_KEY_LENGTH],
    oprf_output: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut scalar_inv = [0u8; PRIVATE_KEY_LENGTH];
    crypto::scalar_invert(blind_scalar, &mut scalar_inv)?;

    let mut unblinded_bytes = [0u8; PUBLIC_KEY_LENGTH];
    crypto::scalar_mult(&scalar_inv, evaluated_element, &mut unblinded_bytes)?;
    scalar_inv.zeroize();

    crypto::sha512_multi(
        &[
            labels::OPRF_CONTEXT,
            &[FINALIZE_DOMAIN],
            input,
            &unblinded_bytes,
        ],
        oprf_output,
    );

    unblinded_bytes.zeroize();
    Ok(())
}

pub trait OprfEvaluator: Send + Sync {
    fn evaluate_oprf(
        &self,
        blinded_element: &[u8; PUBLIC_KEY_LENGTH],
        account_id: &[u8],
    ) -> OpaqueResult<[u8; PUBLIC_KEY_LENGTH]>;

    fn derive_fake_material(&self, account_id: &[u8]) -> OpaqueResult<[u8; HASH_LENGTH]>;

    fn zeroize_secret(&mut self) {}
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InMemoryEvaluator {
    oprf_seed: [u8; OPRF_SEED_LENGTH],
}

impl InMemoryEvaluator {
    pub fn new(oprf_seed: [u8; OPRF_SEED_LENGTH]) -> OpaqueResult<Self> {
        use crate::types::is_all_zero;
        let oprf_seed = Zeroizing::new(oprf_seed);
        if is_all_zero(&*oprf_seed) {
            return Err(OpaqueError::InvalidInput);
        }
        Ok(Self {
            oprf_seed: *oprf_seed,
        })
    }
}

impl OprfEvaluator for InMemoryEvaluator {
    fn zeroize_secret(&mut self) {
        self.oprf_seed.zeroize();
    }

    fn evaluate_oprf(
        &self,
        blinded_element: &[u8; PUBLIC_KEY_LENGTH],
        account_id: &[u8],
    ) -> OpaqueResult<[u8; PUBLIC_KEY_LENGTH]> {
        let mut oprf_key = [0u8; PRIVATE_KEY_LENGTH];
        crypto::derive_oprf_key(&self.oprf_seed, account_id, &mut oprf_key)?;

        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        evaluate(blinded_element, &oprf_key, &mut evaluated)?;
        oprf_key.zeroize();
        Ok(evaluated)
    }

    fn derive_fake_material(&self, account_id: &[u8]) -> OpaqueResult<[u8; HASH_LENGTH]> {
        let mut seed = [0u8; HASH_LENGTH];
        crypto::sha512_multi(
            &[FAKE_CREDENTIALS_CONTEXT, &self.oprf_seed, account_id],
            &mut seed,
        );
        Ok(seed)
    }
}
