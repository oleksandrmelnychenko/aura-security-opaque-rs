// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::crypto;
use crate::types::{pq, pq_labels, OpaqueError, OpaqueResult, CLASSICAL_IKM_LENGTH, HASH_LENGTH};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use zeroize::Zeroize;

const _: () = assert!(
    pq_labels::PQ_COMBINER_CONTEXT.len() + HASH_LENGTH <= 128,
    "labeled_transcript stack buffer overflow"
);

type EK = <MlKem768 as KemCore>::EncapsulationKey;

type DK = <MlKem768 as KemCore>::DecapsulationKey;

pub fn keypair_generate(public_key: &mut [u8], secret_key: &mut [u8]) -> OpaqueResult<()> {
    if public_key.len() != pq::KEM_PUBLIC_KEY_LENGTH
        || secret_key.len() != pq::KEM_SECRET_KEY_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let mut rng = rand_core::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);

    public_key.copy_from_slice(ek.as_bytes().as_ref());
    let mut dk_bytes = dk.as_bytes().to_vec();
    secret_key.copy_from_slice(&dk_bytes);
    dk_bytes.zeroize();
    drop(dk);

    Ok(())
}

pub fn encapsulate(
    public_key: &[u8],
    ciphertext: &mut [u8],
    shared_secret: &mut [u8],
) -> OpaqueResult<()> {
    use ml_kem::kem::Encapsulate;

    if public_key.len() != pq::KEM_PUBLIC_KEY_LENGTH
        || ciphertext.len() != pq::KEM_CIPHERTEXT_LENGTH
        || shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let ek_array: ml_kem::Encoded<EK> = public_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidKemInput)?;
    let ek = EK::from_bytes(&ek_array);
    if ek.as_bytes() != ek_array {
        return Err(OpaqueError::InvalidKemInput);
    }

    let mut rng = rand_core::OsRng;
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| OpaqueError::CryptoError)?;

    ciphertext.copy_from_slice(ct.as_ref());
    shared_secret.copy_from_slice(ss.as_ref());

    Ok(())
}

pub fn decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &mut [u8],
) -> OpaqueResult<()> {
    use ml_kem::kem::Decapsulate;

    if secret_key.len() != pq::KEM_SECRET_KEY_LENGTH
        || ciphertext.len() != pq::KEM_CIPHERTEXT_LENGTH
        || shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let mut dk_array: ml_kem::Encoded<DK> = secret_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidKemInput)?;
    let ct: ml_kem::Ciphertext<MlKem768> = ciphertext
        .try_into()
        .map_err(|_| OpaqueError::InvalidKemInput)?;

    let ss = {
        let dk = DK::from_bytes(&dk_array);
        let result = dk.decapsulate(&ct).map_err(|_| OpaqueError::CryptoError);
        drop(dk);
        result?
    };
    dk_array.zeroize();
    shared_secret.copy_from_slice(ss.as_ref());

    Ok(())
}

pub fn combine_key_material(
    classical_ikm: &[u8],
    pq_shared_secret: &[u8],
    transcript_hash: &[u8],
    prk: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if classical_ikm.len() != CLASSICAL_IKM_LENGTH
        || pq_shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
        || transcript_hash.len() != HASH_LENGTH
    {
        return Err(OpaqueError::InvalidInput);
    }

    let mut combined_ikm = [0u8; pq::COMBINED_IKM_LENGTH];
    combined_ikm[..CLASSICAL_IKM_LENGTH].copy_from_slice(classical_ikm);
    combined_ikm[CLASSICAL_IKM_LENGTH..].copy_from_slice(pq_shared_secret);

    const LABEL_LEN: usize = pq_labels::PQ_COMBINER_CONTEXT.len();
    let mut labeled_transcript = [0u8; LABEL_LEN + HASH_LENGTH];
    labeled_transcript[..LABEL_LEN].copy_from_slice(pq_labels::PQ_COMBINER_CONTEXT);
    labeled_transcript[LABEL_LEN..].copy_from_slice(transcript_hash);

    let result = crypto::key_derivation_extract(&labeled_transcript, &combined_ikm, prk);

    combined_ikm.zeroize();
    labeled_transcript.zeroize();

    result
}
