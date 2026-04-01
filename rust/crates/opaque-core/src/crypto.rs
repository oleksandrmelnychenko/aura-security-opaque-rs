// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::types::{
    is_all_zero, labels, OpaqueError, OpaqueResult, HASH_LENGTH, MAC_LENGTH, NONCE_LENGTH,
    OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH,
    SECRETBOX_MAC_LENGTH,
};
use zeroize::Zeroize;

use crypto_secretbox::aead::{Aead, KeyInit};
use crypto_secretbox::{Key, Nonce, XSalsa20Poly1305};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

const KSF_OPSLIMIT: u32 = 3;

const KSF_MEMLIMIT_KIB: u32 = 256 * 1024;

const ARGON2_SALT_BYTES: usize = 16;

#[inline]
fn decode_non_identity_point(point: &[u8], err: OpaqueError) -> OpaqueResult<RistrettoPoint> {
    if is_all_zero(point) {
        return Err(err);
    }

    let decoded = CompressedRistretto::from_slice(point)
        .map_err(|_| err)?
        .decompress()
        .ok_or(err)?;
    if decoded == RistrettoPoint::identity() {
        return Err(err);
    }
    Ok(decoded)
}

#[inline]
pub fn random_bytes(buf: &mut [u8]) -> OpaqueResult<()> {
    if buf.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
    Ok(())
}

pub fn derive_key_pair(
    seed: &[u8],
    private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    if seed.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut hash = [0u8; HASH_LENGTH];
    let mut hasher = Sha512::new();
    hasher.update(labels::DERIVE_KEYPAIR_CONTEXT);
    hasher.update(seed);
    let mut digest = hasher.finalize();
    hash.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();

    let mut scalar = Scalar::from_bytes_mod_order_wide(&hash);
    private_key.copy_from_slice(scalar.as_bytes());
    hash.zeroize();

    if is_all_zero(private_key) {
        scalar.zeroize();
        return Err(OpaqueError::InvalidInput);
    }

    let mut point = RISTRETTO_BASEPOINT_TABLE * &scalar;
    public_key.copy_from_slice(point.compress().as_bytes());
    point.zeroize();
    scalar.zeroize();
    Ok(())
}

#[inline]
pub fn scalar_mult(
    scalar_bytes: &[u8; PRIVATE_KEY_LENGTH],
    point_bytes: &[u8; PUBLIC_KEY_LENGTH],
    result: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    let mut scalar: Scalar = Option::from(Scalar::from_canonical_bytes(*scalar_bytes))
        .ok_or(OpaqueError::CryptoError)?;
    if is_all_zero(scalar.as_bytes()) {
        scalar.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    let mut point = decode_non_identity_point(point_bytes, OpaqueError::CryptoError)?;
    let mut product = scalar * point;
    point.zeroize();
    scalar.zeroize();
    if product == RistrettoPoint::identity() {
        product.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    result.copy_from_slice(product.compress().as_bytes());
    product.zeroize();
    Ok(())
}

pub fn validate_ristretto_point(point: &[u8]) -> OpaqueResult<()> {
    if point.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    let _ = decode_non_identity_point(point, OpaqueError::InvalidInput)?;
    Ok(())
}

pub fn validate_public_key(key: &[u8]) -> OpaqueResult<()> {
    if key.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidPublicKey);
    }
    let _ = decode_non_identity_point(key, OpaqueError::InvalidPublicKey)?;
    Ok(())
}

pub fn hash_to_scalar(input: &[u8], scalar_out: &mut [u8; PRIVATE_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    let mut digest = Sha512::digest(input);
    hash.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    let mut scalar = Scalar::from_bytes_mod_order_wide(&hash);
    scalar_out.copy_from_slice(scalar.as_bytes());
    scalar.zeroize();
    hash.zeroize();
    Ok(())
}

pub fn hash_to_group(input: &[u8], point_out: &mut [u8; PUBLIC_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    let mut digest = Sha512::digest(input);
    hash.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    let mut point = RistrettoPoint::from_uniform_bytes(&hash);
    point_out.copy_from_slice(point.compress().as_bytes());
    point.zeroize();
    hash.zeroize();
    Ok(())
}

#[inline]
pub fn hmac_sha512(key: &[u8], message: &[u8], mac_out: &mut [u8; MAC_LENGTH]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = <HmacSha512 as Mac>::new_from_slice(key).map_err(|_| OpaqueError::CryptoError)?;
    mac.update(message);
    let result = mac.finalize();
    mac_out.copy_from_slice(&result.into_bytes());
    Ok(())
}

pub fn verify_hmac(key: &[u8], message: &[u8], expected_mac: &[u8]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() || expected_mac.len() != MAC_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    let mut computed = [0u8; MAC_LENGTH];
    hmac_sha512(key, message, &mut computed)?;
    let eq: bool = computed.ct_eq(expected_mac).into();
    computed.zeroize();
    if !eq {
        return Err(OpaqueError::AuthenticationError);
    }
    Ok(())
}

pub fn key_derivation_extract(
    salt: &[u8],
    ikm: &[u8],
    prk: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if salt.is_empty() || ikm.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    hmac_sha512(salt, ikm, prk)
}

pub fn key_derivation_expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> OpaqueResult<()> {
    if prk.is_empty() || okm.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    const HASH_LEN: usize = HASH_LENGTH;
    const MAX_BLOCKS: usize = 255;

    let n = okm.len().div_ceil(HASH_LEN);
    if n > MAX_BLOCKS {
        return Err(OpaqueError::InvalidInput);
    }

    type HmacSha512 = Hmac<Sha512>;

    let mut t_prev = [0u8; HASH_LEN];
    let mut t_current = [0u8; HASH_LEN];

    let result = (|| {
        for i in 1..=n {
            let mut mac =
                <HmacSha512 as Mac>::new_from_slice(prk).map_err(|_| OpaqueError::CryptoError)?;
            if i > 1 {
                mac.update(&t_prev);
            }
            mac.update(info);

            mac.update(&[u8::try_from(i).map_err(|_| OpaqueError::CryptoError)?]);
            t_current.copy_from_slice(&mac.finalize().into_bytes());

            let copy_len = std::cmp::min(HASH_LEN, okm.len() - (i - 1) * HASH_LEN);
            okm[(i - 1) * HASH_LEN..(i - 1) * HASH_LEN + copy_len]
                .copy_from_slice(&t_current[..copy_len]);

            std::mem::swap(&mut t_prev, &mut t_current);
        }
        Ok(())
    })();

    t_prev.zeroize();
    t_current.zeroize();
    result
}

pub fn derive_oprf_key(
    relay_secret: &[u8],
    account_id: &[u8],
    oprf_key: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    if relay_secret.is_empty() || account_id.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut oprf_seed_full = [0u8; MAC_LENGTH];
    hmac_sha512(relay_secret, labels::OPRF_SEED_INFO, &mut oprf_seed_full)?;
    let mut oprf_seed = [0u8; OPRF_SEED_LENGTH];
    oprf_seed.copy_from_slice(&oprf_seed_full[..OPRF_SEED_LENGTH]);
    oprf_seed_full.zeroize();

    type HmacSha512 = Hmac<Sha512>;
    let mut mac_out = [0u8; MAC_LENGTH];

    for counter in 0u8..255 {
        let mut mac = <HmacSha512 as Mac>::new_from_slice(&oprf_seed)
            .map_err(|_| OpaqueError::CryptoError)?;
        mac.update(labels::OPRF_KEY_INFO);
        mac.update(account_id);
        mac.update(&[counter]);
        mac_out.copy_from_slice(&mac.finalize().into_bytes());

        let mac_ref: &[u8; MAC_LENGTH] = mac_out
            .as_slice()
            .try_into()
            .map_err(|_| OpaqueError::CryptoError)?;
        let mut scalar = Scalar::from_bytes_mod_order_wide(mac_ref);
        oprf_key.copy_from_slice(scalar.as_bytes());
        scalar.zeroize();

        if !is_all_zero(oprf_key) {
            mac_out.zeroize();
            oprf_seed.zeroize();
            return Ok(());
        }
    }

    mac_out.zeroize();
    oprf_seed.zeroize();
    Err(OpaqueError::CryptoError)
}

pub fn derive_randomized_password(
    oprf_output: &[u8],
    secure_key: &[u8],
    randomized_pwd: &mut [u8],
) -> OpaqueResult<()> {
    if oprf_output.is_empty() || secure_key.is_empty() || randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut rwd_input = [0u8; HASH_LENGTH];
    sha512_multi(
        &[labels::KSF_CONTEXT, oprf_output, secure_key],
        &mut rwd_input,
    );

    let mut salt_full = [0u8; HASH_LENGTH];
    sha512_multi(&[labels::KSF_SALT_LABEL, oprf_output], &mut salt_full);
    let mut salt = [0u8; ARGON2_SALT_BYTES];
    salt.copy_from_slice(&salt_full[..ARGON2_SALT_BYTES]);

    let params = argon2::Params::new(
        KSF_MEMLIMIT_KIB,
        KSF_OPSLIMIT,
        1,
        Some(randomized_pwd.len()),
    )
    .map_err(|_| OpaqueError::CryptoError)?;

    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon
        .hash_password_into(&rwd_input, &salt, randomized_pwd)
        .map_err(|_| OpaqueError::CryptoError)?;

    rwd_input.zeroize();
    salt_full.zeroize();
    salt.zeroize();
    Ok(())
}

pub fn encrypt_envelope(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &mut [u8],
    auth_tag: &mut [u8; SECRETBOX_MAC_LENGTH],
) -> OpaqueResult<()> {
    if key.len() != SECRETBOX_KEY_LENGTH || plaintext.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(OpaqueError::InvalidInput);
    }

    let key_ref: &Key = key.into();
    let nonce_ref: &Nonce = nonce.as_slice().into();
    let cipher = XSalsa20Poly1305::new(key_ref);

    let mut encrypted = cipher
        .encrypt(nonce_ref, plaintext)
        .map_err(|_| OpaqueError::CryptoError)?;
    if encrypted.len() != SECRETBOX_MAC_LENGTH + plaintext.len() {
        encrypted.zeroize();
        return Err(OpaqueError::CryptoError);
    }

    auth_tag.copy_from_slice(&encrypted[..SECRETBOX_MAC_LENGTH]);
    ciphertext[..plaintext.len()].copy_from_slice(&encrypted[SECRETBOX_MAC_LENGTH..]);
    encrypted.zeroize();
    Ok(())
}

pub fn decrypt_envelope(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    auth_tag: &[u8; SECRETBOX_MAC_LENGTH],
    plaintext: &mut [u8],
) -> OpaqueResult<()> {
    if key.len() != SECRETBOX_KEY_LENGTH || ciphertext.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(OpaqueError::InvalidInput);
    }

    let key_ref: &Key = key.into();
    let nonce_ref: &Nonce = nonce.as_slice().into();
    let cipher = XSalsa20Poly1305::new(key_ref);

    let mut sealed = vec![0u8; SECRETBOX_MAC_LENGTH + ciphertext.len()];
    sealed[..SECRETBOX_MAC_LENGTH].copy_from_slice(auth_tag);
    sealed[SECRETBOX_MAC_LENGTH..].copy_from_slice(ciphertext);

    let mut decrypted = cipher
        .decrypt(nonce_ref, sealed.as_slice())
        .map_err(|_| OpaqueError::AuthenticationError)?;
    sealed.zeroize();

    if decrypted.len() != ciphertext.len() {
        decrypted.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    plaintext[..ciphertext.len()].copy_from_slice(&decrypted);
    decrypted.zeroize();

    Ok(())
}

#[inline]
pub fn random_nonzero_scalar() -> OpaqueResult<[u8; PRIVATE_KEY_LENGTH]> {
    for _ in 0..256 {
        let mut scalar = Scalar::random(&mut rand::rngs::OsRng);
        let bytes = scalar.to_bytes();
        scalar.zeroize();
        if !is_all_zero(&bytes) {
            return Ok(bytes);
        }
    }
    Err(OpaqueError::CryptoError)
}

#[inline]
pub fn scalarmult_base(scalar: &[u8; PRIVATE_KEY_LENGTH]) -> OpaqueResult<[u8; PUBLIC_KEY_LENGTH]> {
    let mut s: Scalar =
        Option::from(Scalar::from_canonical_bytes(*scalar)).ok_or(OpaqueError::CryptoError)?;
    if s == Scalar::ZERO {
        s.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    let mut point = RISTRETTO_BASEPOINT_TABLE * &s;
    s.zeroize();
    if point == RistrettoPoint::identity() {
        point.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    let out = point.compress().to_bytes();
    point.zeroize();
    Ok(out)
}

pub fn scalar_invert(
    scalar: &[u8; PRIVATE_KEY_LENGTH],
    result: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    let mut s: Scalar =
        Option::from(Scalar::from_canonical_bytes(*scalar)).ok_or(OpaqueError::CryptoError)?;
    let mut inv = s.invert();
    s.zeroize();

    if inv == Scalar::ZERO {
        inv.zeroize();
        return Err(OpaqueError::CryptoError);
    }
    result.copy_from_slice(inv.as_bytes());
    inv.zeroize();
    Ok(())
}

#[inline]
pub fn sha512(input: &[u8], out: &mut [u8; HASH_LENGTH]) {
    let mut digest = Sha512::digest(input);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
}

#[inline]
pub fn sha512_multi(parts: &[&[u8]], out: &mut [u8; HASH_LENGTH]) {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    let mut result = hasher.finalize();
    out.copy_from_slice(&result);
    result.as_mut_slice().zeroize();
}
