// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::crypto;
use crate::types::{
    constant_time_eq, labels, Envelope, OpaqueError, OpaqueResult, HASH_LENGTH, NONCE_LENGTH,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH, SECRETBOX_MAC_LENGTH,
};
use zeroize::Zeroize;

const ENVELOPE_KDF_SALT_LEN: usize = labels::ENVELOPE_CONTEXT.len() + PUBLIC_KEY_LENGTH;

fn derive_envelope_key(
    responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    randomized_pwd: &[u8],
    auth_key: &mut [u8; SECRETBOX_KEY_LENGTH],
) -> OpaqueResult<()> {
    let mut salt = [0u8; ENVELOPE_KDF_SALT_LEN];
    salt[..labels::ENVELOPE_CONTEXT.len()].copy_from_slice(labels::ENVELOPE_CONTEXT);
    salt[labels::ENVELOPE_CONTEXT.len()..].copy_from_slice(responder_public_key);
    let mut prk = [0u8; HASH_LENGTH];
    crypto::key_derivation_extract(&salt, randomized_pwd, &mut prk)?;
    salt.zeroize();
    crypto::key_derivation_expand(&prk, labels::ENVELOPE_CONTEXT, auth_key)?;
    prk.zeroize();
    Ok(())
}

pub fn seal(
    randomized_pwd: &[u8],
    responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    initiator_private_key: &[u8; PRIVATE_KEY_LENGTH],
    initiator_public_key: &[u8; PUBLIC_KEY_LENGTH],
    envelope: &mut Envelope,
) -> OpaqueResult<()> {
    if randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if envelope.nonce.len() != NONCE_LENGTH {
        return Err(OpaqueError::InvalidEnvelope);
    }

    crypto::random_bytes(&mut envelope.nonce)?;

    let mut auth_key = [0u8; SECRETBOX_KEY_LENGTH];
    derive_envelope_key(responder_public_key, randomized_pwd, &mut auth_key)?;

    const PLAINTEXT_LEN: usize = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[..PUBLIC_KEY_LENGTH].copy_from_slice(responder_public_key);
    plaintext[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH]
        .copy_from_slice(initiator_private_key);
    plaintext[PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH..].copy_from_slice(initiator_public_key);

    envelope.ciphertext.resize(PLAINTEXT_LEN, 0);
    envelope.auth_tag.resize(SECRETBOX_MAC_LENGTH, 0);
    let nonce: &[u8; NONCE_LENGTH] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;
    let tag: &mut [u8; SECRETBOX_MAC_LENGTH] = envelope
        .auth_tag
        .as_mut_slice()
        .try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;

    crypto::encrypt_envelope(&auth_key, &plaintext, nonce, &mut envelope.ciphertext, tag)?;

    auth_key.zeroize();
    plaintext.zeroize();
    Ok(())
}

pub fn open(
    envelope: &Envelope,
    randomized_pwd: &[u8],
    known_responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    responder_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
    initiator_private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    initiator_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    open_raw(
        &envelope.nonce,
        &envelope.ciphertext,
        &envelope.auth_tag,
        randomized_pwd,
        known_responder_public_key,
        responder_public_key,
        initiator_private_key,
        initiator_public_key,
    )
}

pub fn open_raw(
    nonce: &[u8],
    ciphertext: &[u8],
    auth_tag: &[u8],
    randomized_pwd: &[u8],
    known_responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    responder_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
    initiator_private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    initiator_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    if randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    const PLAINTEXT_LEN: usize = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    if nonce.len() != NONCE_LENGTH || ciphertext.len() != PLAINTEXT_LEN || auth_tag.len() != SECRETBOX_MAC_LENGTH {
        return Err(OpaqueError::InvalidEnvelope);
    }

    let mut auth_key = [0u8; SECRETBOX_KEY_LENGTH];
    derive_envelope_key(known_responder_public_key, randomized_pwd, &mut auth_key)?;

    let mut plaintext = [0u8; PLAINTEXT_LEN];
    let nonce: &[u8; NONCE_LENGTH] = nonce.try_into().map_err(|_| OpaqueError::InvalidEnvelope)?;
    let tag: &[u8; SECRETBOX_MAC_LENGTH] =
        auth_tag.try_into().map_err(|_| OpaqueError::InvalidEnvelope)?;

    let result = crypto::decrypt_envelope(&auth_key, ciphertext, nonce, tag, &mut plaintext);

    auth_key.zeroize();

    let Ok(()) = result else {
        plaintext.zeroize();
        return result;
    };

    responder_public_key.copy_from_slice(&plaintext[..PUBLIC_KEY_LENGTH]);
    initiator_private_key
        .copy_from_slice(&plaintext[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH]);
    initiator_public_key.copy_from_slice(&plaintext[PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH..]);
    plaintext.zeroize();

    let derived_pk = match crypto::scalarmult_base(initiator_private_key) {
        Ok(pk) => pk,
        Err(e) => {
            responder_public_key.zeroize();
            initiator_private_key.zeroize();
            initiator_public_key.zeroize();
            return Err(e);
        }
    };

    if !constant_time_eq(initiator_public_key, &derived_pk) {
        responder_public_key.zeroize();
        initiator_private_key.zeroize();
        initiator_public_key.zeroize();
        return Err(OpaqueError::AuthenticationError);
    }

    Ok(())
}
