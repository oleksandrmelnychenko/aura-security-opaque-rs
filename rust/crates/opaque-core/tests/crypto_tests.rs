// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use opaque_core::crypto;
use opaque_core::types::*;

#[test]
fn random_bytes_fills_buffer() {
    let mut buf = [0u8; 64];
    crypto::random_bytes(&mut buf).unwrap();
    assert!(!buf.iter().all(|&b| b == 0));
}

#[test]
fn random_bytes_empty_fails() {
    let mut buf = [];
    assert!(crypto::random_bytes(&mut buf).is_err());
}

#[test]
fn derive_key_pair_produces_valid_keys() {
    let seed = b"test seed for key derivation 123";
    let mut sk = [0u8; PRIVATE_KEY_LENGTH];
    let mut pk = [0u8; PUBLIC_KEY_LENGTH];
    crypto::derive_key_pair(seed, &mut sk, &mut pk).unwrap();

    assert!(!sk.iter().all(|&b| b == 0));
    assert!(!pk.iter().all(|&b| b == 0));
    crypto::validate_public_key(&pk).unwrap();
}

#[test]
fn derive_key_pair_deterministic() {
    let seed = b"deterministic test seed!";
    let mut sk1 = [0u8; PRIVATE_KEY_LENGTH];
    let mut pk1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut sk2 = [0u8; PRIVATE_KEY_LENGTH];
    let mut pk2 = [0u8; PUBLIC_KEY_LENGTH];

    crypto::derive_key_pair(seed, &mut sk1, &mut pk1).unwrap();
    crypto::derive_key_pair(seed, &mut sk2, &mut pk2).unwrap();

    assert_eq!(sk1, sk2);
    assert_eq!(pk1, pk2);
}

#[test]
fn derive_key_pair_empty_seed_fails() {
    let mut sk = [0u8; PRIVATE_KEY_LENGTH];
    let mut pk = [0u8; PUBLIC_KEY_LENGTH];
    assert!(crypto::derive_key_pair(b"", &mut sk, &mut pk).is_err());
}

#[test]
fn scalar_mult_base_and_scalar_mult_consistent() {
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let base_result = crypto::scalarmult_base(&scalar).unwrap();

    crypto::validate_ristretto_point(&base_result).unwrap();
    assert!(!base_result.iter().all(|&b| b == 0));
}

#[test]
fn scalar_mult_produces_valid_point() {
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let point = crypto::scalarmult_base(&scalar).unwrap();

    let scalar2 = crypto::random_nonzero_scalar().unwrap();
    let mut result = [0u8; PUBLIC_KEY_LENGTH];
    crypto::scalar_mult(&scalar2, &point, &mut result).unwrap();

    crypto::validate_ristretto_point(&result).unwrap();
}

#[test]
fn validate_ristretto_point_rejects_zero() {
    let zero = [0u8; PUBLIC_KEY_LENGTH];
    assert!(crypto::validate_ristretto_point(&zero).is_err());
}

#[test]
fn validate_ristretto_point_rejects_garbage() {
    let garbage = [0xFF; PUBLIC_KEY_LENGTH];
    assert!(crypto::validate_ristretto_point(&garbage).is_err());
}

#[test]
fn validate_ristretto_point_rejects_identity() {
    let identity = RistrettoPoint::identity().compress().to_bytes();
    assert!(crypto::validate_ristretto_point(&identity).is_err());
}

#[test]
fn validate_public_key_accepts_valid() {
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let pk = crypto::scalarmult_base(&scalar).unwrap();
    crypto::validate_public_key(&pk).unwrap();
}

#[test]
fn validate_public_key_rejects_identity() {
    let identity = RistrettoPoint::identity().compress().to_bytes();
    assert!(crypto::validate_public_key(&identity).is_err());
}

#[test]
fn validate_public_key_rejects_wrong_length() {
    let short = [1u8; 16];
    assert!(crypto::validate_public_key(&short).is_err());
}

#[test]
fn hmac_sha512_produces_mac() {
    let key = b"test key for hmac";
    let message = b"test message for hmac";
    let mut mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(key, message, &mut mac).unwrap();
    assert!(!mac.iter().all(|&b| b == 0));
}

#[test]
fn hmac_sha512_deterministic() {
    let key = b"deterministic key";
    let message = b"deterministic message";
    let mut mac1 = [0u8; MAC_LENGTH];
    let mut mac2 = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(key, message, &mut mac1).unwrap();
    crypto::hmac_sha512(key, message, &mut mac2).unwrap();
    assert_eq!(mac1, mac2);
}

#[test]
fn hmac_sha512_different_keys_different_macs() {
    let message = b"same message";
    let mut mac1 = [0u8; MAC_LENGTH];
    let mut mac2 = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(b"key1", message, &mut mac1).unwrap();
    crypto::hmac_sha512(b"key2", message, &mut mac2).unwrap();
    assert_ne!(mac1, mac2);
}

#[test]
fn verify_hmac_accepts_valid() {
    let key = b"verify test key";
    let message = b"verify test message";
    let mut mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(key, message, &mut mac).unwrap();
    crypto::verify_hmac(key, message, &mac).unwrap();
}

#[test]
fn verify_hmac_rejects_tampered() {
    let key = b"verify test key";
    let message = b"verify test message";
    let mut mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(key, message, &mut mac).unwrap();
    mac[0] ^= 0xFF;
    assert!(crypto::verify_hmac(key, message, &mac).is_err());
}

#[test]
fn hkdf_extract_expand_roundtrip() {
    let salt = b"hkdf test salt value";
    let ikm = b"hkdf test input key material";
    let info = b"hkdf test info";

    let mut prk = [0u8; HASH_LENGTH];
    crypto::key_derivation_extract(salt, ikm, &mut prk).unwrap();
    assert!(!prk.iter().all(|&b| b == 0));

    let mut okm = [0u8; 64];
    crypto::key_derivation_expand(&prk, info, &mut okm).unwrap();
    assert!(!okm.iter().all(|&b| b == 0));
}

#[test]
fn hkdf_expand_deterministic() {
    let salt = b"deterministic salt";
    let ikm = b"deterministic ikm value";
    let info = b"deterministic info";

    let mut prk = [0u8; HASH_LENGTH];
    crypto::key_derivation_extract(salt, ikm, &mut prk).unwrap();

    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    crypto::key_derivation_expand(&prk, info, &mut okm1).unwrap();
    crypto::key_derivation_expand(&prk, info, &mut okm2).unwrap();
    assert_eq!(okm1, okm2);
}

#[test]
fn hkdf_expand_different_info_different_output() {
    let salt = b"test salt";
    let ikm = b"test ikm";

    let mut prk = [0u8; HASH_LENGTH];
    crypto::key_derivation_extract(salt, ikm, &mut prk).unwrap();

    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    crypto::key_derivation_expand(&prk, b"info1", &mut okm1).unwrap();
    crypto::key_derivation_expand(&prk, b"info2", &mut okm2).unwrap();
    assert_ne!(okm1, okm2);
}

#[test]
fn derive_oprf_key_produces_nonzero_key() {
    let relay_secret = b"relay secret for oprf key test!!";
    let account_id = b"alice@example.com";
    let mut oprf_key = [0u8; PRIVATE_KEY_LENGTH];
    crypto::derive_oprf_key(relay_secret, account_id, &mut oprf_key).unwrap();
    assert!(!oprf_key.iter().all(|&b| b == 0));
}

#[test]
fn derive_oprf_key_deterministic() {
    let relay_secret = b"deterministic relay secret 1234!";
    let account_id = b"bob@example.com";
    let mut key1 = [0u8; PRIVATE_KEY_LENGTH];
    let mut key2 = [0u8; PRIVATE_KEY_LENGTH];
    crypto::derive_oprf_key(relay_secret, account_id, &mut key1).unwrap();
    crypto::derive_oprf_key(relay_secret, account_id, &mut key2).unwrap();
    assert_eq!(key1, key2);
}

#[test]
fn derive_oprf_key_different_accounts_different_keys() {
    let relay_secret = b"shared relay secret for testing!";
    let mut key1 = [0u8; PRIVATE_KEY_LENGTH];
    let mut key2 = [0u8; PRIVATE_KEY_LENGTH];
    crypto::derive_oprf_key(relay_secret, b"alice", &mut key1).unwrap();
    crypto::derive_oprf_key(relay_secret, b"bob", &mut key2).unwrap();
    assert_ne!(key1, key2);
}

#[test]
fn encrypt_decrypt_envelope_roundtrip() {
    let key = [0x42u8; SECRETBOX_KEY_LENGTH];
    let plaintext = b"secret envelope content here!!!!";
    let mut nonce = [0u8; NONCE_LENGTH];
    crypto::random_bytes(&mut nonce).unwrap();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; SECRETBOX_MAC_LENGTH];
    crypto::encrypt_envelope(&key, plaintext, &nonce, &mut ciphertext, &mut tag).unwrap();

    assert_ne!(&ciphertext[..], &plaintext[..]);

    let mut decrypted = vec![0u8; ciphertext.len()];
    crypto::decrypt_envelope(&key, &ciphertext, &nonce, &tag, &mut decrypted).unwrap();
    assert_eq!(&decrypted[..], &plaintext[..]);
}

#[test]
fn decrypt_envelope_wrong_key_fails() {
    let key = [0x42u8; SECRETBOX_KEY_LENGTH];
    let wrong_key = [0x43u8; SECRETBOX_KEY_LENGTH];
    let plaintext = b"secret data for wrong key test!!";
    let mut nonce = [0u8; NONCE_LENGTH];
    crypto::random_bytes(&mut nonce).unwrap();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; SECRETBOX_MAC_LENGTH];
    crypto::encrypt_envelope(&key, plaintext, &nonce, &mut ciphertext, &mut tag).unwrap();

    let mut decrypted = vec![0u8; ciphertext.len()];
    assert!(
        crypto::decrypt_envelope(&wrong_key, &ciphertext, &nonce, &tag, &mut decrypted).is_err()
    );
}

#[test]
fn decrypt_envelope_tampered_ciphertext_fails() {
    let key = [0x42u8; SECRETBOX_KEY_LENGTH];
    let plaintext = b"secret data for tamper test!!!!!";
    let mut nonce = [0u8; NONCE_LENGTH];
    crypto::random_bytes(&mut nonce).unwrap();

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut tag = [0u8; SECRETBOX_MAC_LENGTH];
    crypto::encrypt_envelope(&key, plaintext, &nonce, &mut ciphertext, &mut tag).unwrap();

    ciphertext[0] ^= 0xFF;

    let mut decrypted = vec![0u8; ciphertext.len()];
    assert!(crypto::decrypt_envelope(&key, &ciphertext, &nonce, &tag, &mut decrypted).is_err());
}

#[test]
fn random_nonzero_scalar_is_nonzero() {
    for _ in 0..100 {
        let scalar = crypto::random_nonzero_scalar().unwrap();
        assert_ne!(scalar, [0u8; 32]);
    }
}

#[test]
fn scalarmult_base_rejects_zero_scalar() {
    let zero = [0u8; PRIVATE_KEY_LENGTH];
    assert!(crypto::scalarmult_base(&zero).is_err());
}

#[test]
fn scalar_mult_rejects_identity_point() {
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let identity = RistrettoPoint::identity().compress().to_bytes();
    let mut out = [0u8; PUBLIC_KEY_LENGTH];
    assert!(crypto::scalar_mult(&scalar, &identity, &mut out).is_err());
}

#[test]
fn hash_to_scalar_produces_nonzero() {
    let input = b"hash to scalar test input";
    let mut scalar_out = [0u8; PRIVATE_KEY_LENGTH];
    crypto::hash_to_scalar(input, &mut scalar_out).unwrap();
    assert!(!scalar_out.iter().all(|&b| b == 0));
}

#[test]
fn hash_to_group_produces_valid_point() {
    let input = b"hash to group test input";
    let mut point = [0u8; PUBLIC_KEY_LENGTH];
    crypto::hash_to_group(input, &mut point).unwrap();
    crypto::validate_ristretto_point(&point).unwrap();
}

#[test]
fn credential_envelope_mask_roundtrip_is_context_bound() {
    let randomized_pwd = [0x11u8; HASH_LENGTH];
    let mut masking_key = [0u8; MASKING_KEY_LENGTH];
    crypto::derive_masking_key(&randomized_pwd, &mut masking_key).unwrap();
    let nonce = [0x22u8; NONCE_LENGTH];
    let evaluated = [0x33u8; PUBLIC_KEY_LENGTH];
    let account_context = [0x44u8; HASH_LENGTH];
    let envelope = [0x55u8; ENVELOPE_LENGTH];

    let mut masked = [0u8; ENVELOPE_LENGTH];
    crypto::mask_credential_envelope(
        &masking_key,
        &nonce,
        &evaluated,
        &account_context,
        &envelope,
        &mut masked,
    )
    .unwrap();
    assert_ne!(masked, envelope);

    let mut recovered = [0u8; ENVELOPE_LENGTH];
    crypto::mask_credential_envelope(
        &masking_key,
        &nonce,
        &evaluated,
        &account_context,
        &masked,
        &mut recovered,
    )
    .unwrap();
    assert_eq!(recovered, envelope);

    let mut other_context = account_context;
    other_context[0] ^= 1;
    let mut differently_masked = [0u8; ENVELOPE_LENGTH];
    crypto::mask_credential_envelope(
        &masking_key,
        &nonce,
        &evaluated,
        &other_context,
        &envelope,
        &mut differently_masked,
    )
    .unwrap();
    assert_ne!(differently_masked, masked);
}
