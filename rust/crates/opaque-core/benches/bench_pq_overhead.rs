// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{criterion_group, criterion_main, Criterion};
use opaque_core::crypto;
use opaque_core::oprf;
use opaque_core::pq_kem;
use opaque_core::types::*;

const BENCH_ADDITIONAL_KEY_INFO: &[u8] = b"benchmark/additional-key";

fn bench_ke1(c: &mut Criterion) {
    let input = b"benchmark password";
    let mut group = c.benchmark_group("pq_overhead/ke1");

    group.bench_function("classic", |b| {
        let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
        b.iter(|| {
            oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
            let eph_sk = crypto::random_nonzero_scalar().unwrap();
            let _eph_pk = crypto::scalarmult_base(&eph_sk).unwrap();
        })
    });

    group.bench_function("hybrid", |b| {
        let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
        let mut kem_pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
        let mut kem_sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
        b.iter(|| {
            oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
            let eph_sk = crypto::random_nonzero_scalar().unwrap();
            let _eph_pk = crypto::scalarmult_base(&eph_sk).unwrap();
            pq_kem::keypair_generate(&mut kem_pk, &mut kem_sk).unwrap();
        })
    });

    group.finish();
}

fn bench_ke2_no_ksf(c: &mut Criterion) {
    let resp_sk = crypto::random_nonzero_scalar().unwrap();
    let resp_eph_sk = crypto::random_nonzero_scalar().unwrap();
    let _resp_eph_pk = crypto::scalarmult_base(&resp_eph_sk).unwrap();
    let init_static_sk = crypto::random_nonzero_scalar().unwrap();
    let init_static_pk = crypto::scalarmult_base(&init_static_sk).unwrap();
    let init_eph_sk = crypto::random_nonzero_scalar().unwrap();
    let init_eph_pk = crypto::scalarmult_base(&init_eph_sk).unwrap();

    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(b"password", &mut blinded, &mut blind_scalar).unwrap();
    let oprf_key = crypto::random_nonzero_scalar().unwrap();

    let mut kem_pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut kem_sk_unused = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut kem_pk, &mut kem_sk_unused).unwrap();

    let transcript_hash = [0x44u8; HASH_LENGTH];
    let mac_input = [0x43u8; 256];

    let mut group = c.benchmark_group("pq_overhead/ke2_no_ksf");

    group.bench_function("classic", |b| {
        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let mut prk = [0u8; HASH_LENGTH];
        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; EXPORT_KEY_LENGTH];
        let mut resp_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac_key = [0u8; MAC_LENGTH];
        let mut resp_mac = [0u8; MAC_LENGTH];
        let mut init_mac = [0u8; MAC_LENGTH];
        b.iter(|| {
            oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();
            crypto::scalar_mult(&resp_sk, &init_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&resp_sk, &init_eph_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_static_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            crypto::key_derivation_extract(labels::HKDF_SALT, &ikm, &mut prk).unwrap();
            crypto::key_derivation_expand(&prk, labels::SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::RESPONDER_MAC_INFO, &mut resp_mac_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::INITIATOR_MAC_INFO, &mut init_mac_key)
                .unwrap();
            crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut resp_mac).unwrap();
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac).unwrap();
        })
    });

    group.bench_function("hybrid", |b| {
        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let mut kem_ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
        let mut kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let mut prk = [0u8; HASH_LENGTH];
        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; EXPORT_KEY_LENGTH];
        let mut resp_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac_key = [0u8; MAC_LENGTH];
        let mut resp_mac = [0u8; MAC_LENGTH];
        let mut init_mac = [0u8; MAC_LENGTH];
        b.iter(|| {
            oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();
            crypto::scalar_mult(&resp_sk, &init_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&resp_sk, &init_eph_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_static_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            pq_kem::encapsulate(&kem_pk, &mut kem_ct, &mut kem_ss).unwrap();
            pq_kem::combine_key_material(&ikm, &kem_ss, &transcript_hash, &mut prk).unwrap();
            crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_RESPONDER_MAC_INFO,
                &mut resp_mac_key,
            )
            .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_INITIATOR_MAC_INFO,
                &mut init_mac_key,
            )
            .unwrap();
            crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut resp_mac).unwrap();
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac).unwrap();
        })
    });

    group.finish();
}

fn bench_ke3_no_ksf(c: &mut Criterion) {
    let init_static_sk = crypto::random_nonzero_scalar().unwrap();
    let init_eph_sk = crypto::random_nonzero_scalar().unwrap();
    let _init_eph_pk = crypto::scalarmult_base(&init_eph_sk).unwrap();
    let resp_static_sk = crypto::random_nonzero_scalar().unwrap();
    let resp_static_pk = crypto::scalarmult_base(&resp_static_sk).unwrap();
    let resp_eph_sk = crypto::random_nonzero_scalar().unwrap();
    let resp_eph_pk = crypto::scalarmult_base(&resp_eph_sk).unwrap();

    let input = b"benchmark password";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
    let oprf_key = crypto::random_nonzero_scalar().unwrap();
    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();

    let mut kem_pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut kem_sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut kem_pk, &mut kem_sk).unwrap();
    let mut kem_ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut kem_ss_enc = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&kem_pk, &mut kem_ct, &mut kem_ss_enc).unwrap();

    let transcript_hash = [0x44u8; HASH_LENGTH];
    let mac_input = [0x43u8; 256];
    let dummy_resp_mac_key = [0x99u8; MAC_LENGTH];
    let mut valid_resp_mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(&dummy_resp_mac_key, &mac_input, &mut valid_resp_mac).unwrap();

    let mut group = c.benchmark_group("pq_overhead/ke3_no_ksf");

    group.bench_function("classic", |b| {
        let mut oprf_output = [0u8; HASH_LENGTH];
        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let mut prk = [0u8; HASH_LENGTH];
        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; EXPORT_KEY_LENGTH];
        let mut resp_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac = [0u8; MAC_LENGTH];
        b.iter(|| {
            oprf::finalize(input, &blind_scalar, &evaluated, &mut oprf_output).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_static_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_eph_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            crypto::key_derivation_extract(labels::HKDF_SALT, &ikm, &mut prk).unwrap();
            crypto::key_derivation_expand(&prk, labels::SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::RESPONDER_MAC_INFO, &mut resp_mac_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::INITIATOR_MAC_INFO, &mut init_mac_key)
                .unwrap();
            let _ = crypto::verify_hmac(&dummy_resp_mac_key, &mac_input, &valid_resp_mac);
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac).unwrap();
        })
    });

    group.bench_function("hybrid", |b| {
        let mut oprf_output = [0u8; HASH_LENGTH];
        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let mut kem_ss_dec = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let mut prk = [0u8; HASH_LENGTH];
        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; EXPORT_KEY_LENGTH];
        let mut resp_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac_key = [0u8; MAC_LENGTH];
        let mut init_mac = [0u8; MAC_LENGTH];
        b.iter(|| {
            oprf::finalize(input, &blind_scalar, &evaluated, &mut oprf_output).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_static_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_eph_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            pq_kem::decapsulate(&kem_sk, &kem_ct, &mut kem_ss_dec).unwrap();
            pq_kem::combine_key_material(&ikm, &kem_ss_dec, &transcript_hash, &mut prk).unwrap();
            crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_RESPONDER_MAC_INFO,
                &mut resp_mac_key,
            )
            .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_INITIATOR_MAC_INFO,
                &mut init_mac_key,
            )
            .unwrap();
            let _ = crypto::verify_hmac(&dummy_resp_mac_key, &mac_input, &valid_resp_mac);
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac).unwrap();
        })
    });

    group.finish();
}

fn bench_full_ake_no_ksf(c: &mut Criterion) {
    let resp_static_sk = crypto::random_nonzero_scalar().unwrap();
    let resp_static_pk = crypto::scalarmult_base(&resp_static_sk).unwrap();
    let init_static_sk = crypto::random_nonzero_scalar().unwrap();
    let init_static_pk = crypto::scalarmult_base(&init_static_sk).unwrap();

    let input = b"benchmark password";
    let oprf_key = crypto::random_nonzero_scalar().unwrap();
    let transcript_hash = [0x44u8; HASH_LENGTH];
    let mac_input = [0x43u8; 256];

    let mut group = c.benchmark_group("pq_overhead/full_ake_no_ksf");

    group.bench_function("classic", |b| {
        b.iter(|| {
            let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
            let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
            oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
            let init_eph_sk = crypto::random_nonzero_scalar().unwrap();
            let init_eph_pk = crypto::scalarmult_base(&init_eph_sk).unwrap();

            let resp_eph_sk = crypto::random_nonzero_scalar().unwrap();
            let resp_eph_pk = crypto::scalarmult_base(&resp_eph_sk).unwrap();
            let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
            oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();
            let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
            crypto::scalar_mult(&resp_static_sk, &init_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&resp_static_sk, &init_eph_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_static_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            let mut prk = [0u8; HASH_LENGTH];
            crypto::key_derivation_extract(labels::HKDF_SALT, &ikm, &mut prk).unwrap();
            let mut session_key = [0u8; HASH_LENGTH];
            let mut master_key = [0u8; EXPORT_KEY_LENGTH];
            let mut resp_mac_key = [0u8; MAC_LENGTH];
            let mut init_mac_key = [0u8; MAC_LENGTH];
            let mut resp_mac = [0u8; MAC_LENGTH];
            let mut init_mac_r = [0u8; MAC_LENGTH];
            crypto::key_derivation_expand(&prk, labels::SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::RESPONDER_MAC_INFO, &mut resp_mac_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, labels::INITIATOR_MAC_INFO, &mut init_mac_key)
                .unwrap();
            crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut resp_mac).unwrap();
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac_r).unwrap();

            let mut oprf_output = [0u8; HASH_LENGTH];
            oprf::finalize(input, &blind_scalar, &evaluated, &mut oprf_output).unwrap();
            let mut dh5 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh6 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh7 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh8 = [0u8; PUBLIC_KEY_LENGTH];
            crypto::scalar_mult(&init_static_sk, &resp_static_pk, &mut dh5).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_static_pk, &mut dh6).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_eph_pk, &mut dh7).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_eph_pk, &mut dh8).unwrap();
            let mut ikm2 = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm2[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh5);
            ikm2[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh6);
            ikm2[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh7);
            ikm2[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh8);
            let mut prk2 = [0u8; HASH_LENGTH];
            crypto::key_derivation_extract(labels::HKDF_SALT, &ikm2, &mut prk2).unwrap();
            let mut resp_mac_key2 = [0u8; MAC_LENGTH];
            let mut init_mac_key2 = [0u8; MAC_LENGTH];
            let mut init_mac2 = [0u8; MAC_LENGTH];
            crypto::key_derivation_expand(&prk2, labels::SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk2, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(&prk2, labels::RESPONDER_MAC_INFO, &mut resp_mac_key2)
                .unwrap();
            crypto::key_derivation_expand(&prk2, labels::INITIATOR_MAC_INFO, &mut init_mac_key2)
                .unwrap();
            let _ = crypto::verify_hmac(&resp_mac_key2, &mac_input, &resp_mac);
            crypto::hmac_sha512(&init_mac_key2, &mac_input, &mut init_mac2).unwrap();
        })
    });

    group.bench_function("hybrid", |b| {
        b.iter(|| {
            let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
            let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
            oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
            let init_eph_sk = crypto::random_nonzero_scalar().unwrap();
            let init_eph_pk = crypto::scalarmult_base(&init_eph_sk).unwrap();
            let mut kem_pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
            let mut kem_sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
            pq_kem::keypair_generate(&mut kem_pk, &mut kem_sk).unwrap();

            let resp_eph_sk = crypto::random_nonzero_scalar().unwrap();
            let resp_eph_pk = crypto::scalarmult_base(&resp_eph_sk).unwrap();
            let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
            oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();
            let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
            crypto::scalar_mult(&resp_static_sk, &init_static_pk, &mut dh1).unwrap();
            crypto::scalar_mult(&resp_static_sk, &init_eph_pk, &mut dh2).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_static_pk, &mut dh3).unwrap();
            crypto::scalar_mult(&resp_eph_sk, &init_eph_pk, &mut dh4).unwrap();
            let mut ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
            ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
            ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
            ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);
            let mut kem_ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
            let mut kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
            pq_kem::encapsulate(&kem_pk, &mut kem_ct, &mut kem_ss).unwrap();
            let mut prk = [0u8; HASH_LENGTH];
            pq_kem::combine_key_material(&ikm, &kem_ss, &transcript_hash, &mut prk).unwrap();
            let mut session_key = [0u8; HASH_LENGTH];
            let mut master_key = [0u8; EXPORT_KEY_LENGTH];
            let mut resp_mac_key = [0u8; MAC_LENGTH];
            let mut init_mac_key = [0u8; MAC_LENGTH];
            let mut resp_mac = [0u8; MAC_LENGTH];
            let mut init_mac_r = [0u8; MAC_LENGTH];
            crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_RESPONDER_MAC_INFO,
                &mut resp_mac_key,
            )
            .unwrap();
            crypto::key_derivation_expand(
                &prk,
                pq_labels::PQ_INITIATOR_MAC_INFO,
                &mut init_mac_key,
            )
            .unwrap();
            crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut resp_mac).unwrap();
            crypto::hmac_sha512(&init_mac_key, &mac_input, &mut init_mac_r).unwrap();

            let mut oprf_output = [0u8; HASH_LENGTH];
            oprf::finalize(input, &blind_scalar, &evaluated, &mut oprf_output).unwrap();
            let mut dh5 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh6 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh7 = [0u8; PUBLIC_KEY_LENGTH];
            let mut dh8 = [0u8; PUBLIC_KEY_LENGTH];
            crypto::scalar_mult(&init_static_sk, &resp_static_pk, &mut dh5).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_static_pk, &mut dh6).unwrap();
            crypto::scalar_mult(&init_static_sk, &resp_eph_pk, &mut dh7).unwrap();
            crypto::scalar_mult(&init_eph_sk, &resp_eph_pk, &mut dh8).unwrap();
            let mut ikm2 = [0u8; 4 * PUBLIC_KEY_LENGTH];
            ikm2[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh5);
            ikm2[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh6);
            ikm2[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh7);
            ikm2[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh8);
            let mut kem_ss_dec = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
            pq_kem::decapsulate(&kem_sk, &kem_ct, &mut kem_ss_dec).unwrap();
            let mut prk2 = [0u8; HASH_LENGTH];
            pq_kem::combine_key_material(&ikm2, &kem_ss_dec, &transcript_hash, &mut prk2).unwrap();
            let mut resp_mac_key2 = [0u8; MAC_LENGTH];
            let mut init_mac_key2 = [0u8; MAC_LENGTH];
            let mut init_mac2 = [0u8; MAC_LENGTH];
            crypto::key_derivation_expand(&prk2, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)
                .unwrap();
            crypto::key_derivation_expand(&prk2, BENCH_ADDITIONAL_KEY_INFO, &mut master_key)
                .unwrap();
            crypto::key_derivation_expand(
                &prk2,
                pq_labels::PQ_RESPONDER_MAC_INFO,
                &mut resp_mac_key2,
            )
            .unwrap();
            crypto::key_derivation_expand(
                &prk2,
                pq_labels::PQ_INITIATOR_MAC_INFO,
                &mut init_mac_key2,
            )
            .unwrap();
            let _ = crypto::verify_hmac(&resp_mac_key2, &mac_input, &resp_mac);
            crypto::hmac_sha512(&init_mac_key2, &mac_input, &mut init_mac2).unwrap();
        })
    });

    group.finish();
}

criterion_group!(
    pq_overhead,
    bench_ke1,
    bench_ke2_no_ksf,
    bench_ke3_no_ksf,
    bench_full_ake_no_ksf,
);
criterion_main!(pq_overhead);
