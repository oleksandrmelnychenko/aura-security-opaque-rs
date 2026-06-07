// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{criterion_group, criterion_main, Criterion};
use opaque_core::crypto;
use opaque_core::oprf;
use opaque_core::pq_kem;
use opaque_core::types::*;

fn bench_ristretto_keygen(c: &mut Criterion) {
    c.bench_function("ristretto255/keygen", |b| {
        b.iter(|| {
            let scalar = crypto::random_nonzero_scalar().unwrap();
            crypto::scalarmult_base(&scalar).unwrap()
        })
    });
}

fn bench_ristretto_dh(c: &mut Criterion) {
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let point = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();

    c.bench_function("ristretto255/single_dh", |b| {
        let mut result = [0u8; PUBLIC_KEY_LENGTH];
        b.iter(|| {
            crypto::scalar_mult(&scalar, &point, &mut result).unwrap();
        })
    });
}

fn bench_ristretto_3dh(c: &mut Criterion) {
    let sk1 = crypto::random_nonzero_scalar().unwrap();
    let sk2 = crypto::random_nonzero_scalar().unwrap();
    let sk3 = crypto::random_nonzero_scalar().unwrap();
    let pk1 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();
    let pk2 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();
    let pk3 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();

    c.bench_function("ristretto255/3dh", |b| {
        let mut r1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut r2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut r3 = [0u8; PUBLIC_KEY_LENGTH];
        b.iter(|| {
            crypto::scalar_mult(&sk1, &pk1, &mut r1).unwrap();
            crypto::scalar_mult(&sk2, &pk2, &mut r2).unwrap();
            crypto::scalar_mult(&sk3, &pk3, &mut r3).unwrap();
        })
    });
}

fn bench_ristretto_4dh(c: &mut Criterion) {
    let sk1 = crypto::random_nonzero_scalar().unwrap();
    let sk2 = crypto::random_nonzero_scalar().unwrap();
    let sk3 = crypto::random_nonzero_scalar().unwrap();
    let sk4 = crypto::random_nonzero_scalar().unwrap();
    let pk1 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();
    let pk2 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();
    let pk3 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();
    let pk4 = crypto::scalarmult_base(&crypto::random_nonzero_scalar().unwrap()).unwrap();

    c.bench_function("ristretto255/4dh", |b| {
        let mut r1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut r2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut r3 = [0u8; PUBLIC_KEY_LENGTH];
        let mut r4 = [0u8; PUBLIC_KEY_LENGTH];
        b.iter(|| {
            crypto::scalar_mult(&sk1, &pk1, &mut r1).unwrap();
            crypto::scalar_mult(&sk2, &pk2, &mut r2).unwrap();
            crypto::scalar_mult(&sk3, &pk3, &mut r3).unwrap();
            crypto::scalar_mult(&sk4, &pk4, &mut r4).unwrap();
        })
    });
}

fn bench_mlkem_keygen(c: &mut Criterion) {
    c.bench_function("ml-kem-768/keygen", |b| {
        let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
        let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
        b.iter(|| {
            pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();
        })
    });
}

fn bench_mlkem_encapsulate(c: &mut Criterion) {
    let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();

    c.bench_function("ml-kem-768/encapsulate", |b| {
        let mut ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
        let mut ss = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
        b.iter(|| {
            pq_kem::encapsulate(&pk, &mut ct, &mut ss).unwrap();
        })
    });
}

fn bench_mlkem_decapsulate(c: &mut Criterion) {
    let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();

    let mut ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut ss = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&pk, &mut ct, &mut ss).unwrap();

    c.bench_function("ml-kem-768/decapsulate", |b| {
        let mut ss_out = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
        b.iter(|| {
            pq_kem::decapsulate(&sk, &ct, &mut ss_out).unwrap();
        })
    });
}

fn bench_mlkem_full_round(c: &mut Criterion) {
    c.bench_function("ml-kem-768/full_round", |b| {
        let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
        let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
        let mut ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
        let mut ss_enc = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let mut ss_dec = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
        b.iter(|| {
            pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();
            pq_kem::encapsulate(&pk, &mut ct, &mut ss_enc).unwrap();
            pq_kem::decapsulate(&sk, &ct, &mut ss_dec).unwrap();
        })
    });
}

fn bench_oprf_blind(c: &mut Criterion) {
    let input = b"benchmark password input";
    c.bench_function("oprf/blind", |b| {
        let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
        b.iter(|| {
            oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();
        })
    });
}

fn bench_oprf_evaluate(c: &mut Criterion) {
    let input = b"benchmark password input";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    let server_key = crypto::random_nonzero_scalar().unwrap();

    c.bench_function("oprf/evaluate", |b| {
        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        b.iter(|| {
            oprf::evaluate(&blinded, &server_key, &mut evaluated).unwrap();
        })
    });
}

fn bench_oprf_finalize(c: &mut Criterion) {
    let input = b"benchmark password input";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    let server_key = crypto::random_nonzero_scalar().unwrap();
    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &server_key, &mut evaluated).unwrap();

    c.bench_function("oprf/finalize", |b| {
        let mut output = [0u8; HASH_LENGTH];
        b.iter(|| {
            oprf::finalize(input, &blind_scalar, &evaluated, &mut output).unwrap();
        })
    });
}

fn bench_hkdf_extract(c: &mut Criterion) {
    let salt = [0x42u8; 64];
    let ikm = [0x43u8; 128];

    c.bench_function("hkdf/extract", |b| {
        let mut prk = [0u8; HASH_LENGTH];
        b.iter(|| {
            crypto::key_derivation_extract(&salt, &ikm, &mut prk).unwrap();
        })
    });
}

fn bench_hkdf_expand(c: &mut Criterion) {
    let salt = [0x42u8; 64];
    let ikm = [0x43u8; 128];
    let mut prk = [0u8; HASH_LENGTH];
    crypto::key_derivation_extract(&salt, &ikm, &mut prk).unwrap();

    c.bench_function("hkdf/expand_64B", |b| {
        let mut okm = [0u8; 64];
        b.iter(|| {
            crypto::key_derivation_expand(&prk, b"bench info", &mut okm).unwrap();
        })
    });
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let key = [0x42u8; 64];
    let message = [0x43u8; 256];

    c.bench_function("hmac-sha512/256B", |b| {
        let mut mac = [0u8; MAC_LENGTH];
        b.iter(|| {
            crypto::hmac_sha512(&key, &message, &mut mac).unwrap();
        })
    });
}

fn bench_aead_encrypt(c: &mut Criterion) {
    let key = [0x42u8; SECRETBOX_KEY_LENGTH];
    let plaintext = [0x43u8; 96];
    let nonce = [0u8; NONCE_LENGTH];

    c.bench_function("xsalsa20-poly1305/encrypt_96B", |b| {
        let mut ct = vec![0u8; plaintext.len()];
        let mut tag = [0u8; SECRETBOX_MAC_LENGTH];
        b.iter(|| {
            crypto::encrypt_envelope(&key, &plaintext, &nonce, &mut ct, &mut tag).unwrap();
        })
    });
}

fn bench_aead_decrypt(c: &mut Criterion) {
    let key = [0x42u8; SECRETBOX_KEY_LENGTH];
    let plaintext = [0x43u8; 96];
    let mut nonce = [0u8; NONCE_LENGTH];
    crypto::random_bytes(&mut nonce).unwrap();

    let mut ct = vec![0u8; plaintext.len()];
    let mut tag = [0u8; SECRETBOX_MAC_LENGTH];
    crypto::encrypt_envelope(&key, &plaintext, &nonce, &mut ct, &mut tag).unwrap();

    c.bench_function("xsalsa20-poly1305/decrypt_96B", |b| {
        let mut pt = vec![0u8; ct.len()];
        b.iter(|| {
            crypto::decrypt_envelope(&key, &ct, &nonce, &tag, &mut pt).unwrap();
        })
    });
}

fn bench_argon2id(c: &mut Criterion) {
    let oprf_output = [0x42u8; HASH_LENGTH];
    let secure_key = b"benchmark password";

    let mut group = c.benchmark_group("argon2id");
    group.sample_size(10);
    group.bench_function("moderate_params", |b| {
        let mut out = [0u8; HASH_LENGTH];
        b.iter(|| {
            crypto::derive_randomized_password(&oprf_output, secure_key, &mut out).unwrap();
        })
    });
    group.finish();
}

fn bench_pq_combiner(c: &mut Criterion) {
    let classical_ikm = [0x42u8; 128];
    let pq_ss = [0x43u8; pq::KEM_SHARED_SECRET_LENGTH];
    let transcript_hash = [0x44u8; HASH_LENGTH];

    c.bench_function("pq_combiner/combine", |b| {
        let mut prk = [0u8; HASH_LENGTH];
        b.iter(|| {
            pq_kem::combine_key_material(&classical_ikm, &pq_ss, &transcript_hash, &mut prk)
                .unwrap();
        })
    });
}

criterion_group!(
    ristretto,
    bench_ristretto_keygen,
    bench_ristretto_dh,
    bench_ristretto_3dh,
    bench_ristretto_4dh,
);
criterion_group!(
    mlkem,
    bench_mlkem_keygen,
    bench_mlkem_encapsulate,
    bench_mlkem_decapsulate,
    bench_mlkem_full_round,
);
criterion_group!(
    oprf_benches,
    bench_oprf_blind,
    bench_oprf_evaluate,
    bench_oprf_finalize,
);
criterion_group!(hkdf, bench_hkdf_extract, bench_hkdf_expand,);
criterion_group!(hmac, bench_hmac_sha512,);
criterion_group!(aead, bench_aead_encrypt, bench_aead_decrypt,);
criterion_group!(argon2, bench_argon2id,);
criterion_group!(pq_combiner, bench_pq_combiner,);
criterion_main!(
    ristretto,
    mlkem,
    oprf_benches,
    hkdf,
    hmac,
    aead,
    argon2,
    pq_combiner
);
