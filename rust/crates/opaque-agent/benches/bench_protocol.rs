// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{criterion_group, criterion_main, Criterion};
use opaque_agent::*;
use opaque_core::{crypto, pq_kem};
use opaque_core::protocol;
use opaque_core::types::*;
use opaque_relay::*;

const ACCOUNT_ID: &[u8] = b"bench@example.com";
const PASSWORD: &[u8] = b"benchmark password for protocol";

fn serialize_req(req: &RegistrationRequest) -> Vec<u8> {
    let mut w = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
    protocol::write_registration_request(&req.data, &mut w).unwrap();
    w
}

fn serialize_resp(resp: &RegistrationResponse) -> Vec<u8> {
    let mut w = vec![0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
    protocol::write_registration_response(
        &resp.data[..PUBLIC_KEY_LENGTH],
        &resp.data[PUBLIC_KEY_LENGTH..],
        &mut w,
    )
    .unwrap();
    w
}

fn setup_registered() -> (OpaqueResponder, Vec<u8>) {
    let responder = OpaqueResponder::generate().unwrap();

    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(&responder, &serialize_req(&req), ACCOUNT_ID, &mut resp).unwrap();

    let mut record = RegistrationRecord::new();
    finalize_registration(&initiator, &serialize_resp(&resp), &mut state, &mut record).unwrap();

    let mut record_bytes = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(
        &record.envelope,
        &record.initiator_public_key,
        &mut record_bytes,
    )
    .unwrap();

    (responder, record_bytes)
}

fn bench_registration_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("registration");
    group.bench_function("create_request", |b| {
        b.iter(|| {
            let mut state = InitiatorState::new();
            let mut req = RegistrationRequest::new();
            create_registration_request(PASSWORD, &mut req, &mut state).unwrap();
        })
    });
    group.finish();
}

fn bench_registration_response(c: &mut Criterion) {
    let responder = OpaqueResponder::generate().unwrap();

    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

    let req_wire = serialize_req(&req);

    let mut group = c.benchmark_group("registration");
    group.bench_function("create_response", |b| {
        let mut resp = RegistrationResponse::new();
        b.iter(|| {
            create_registration_response(&responder, &req_wire, ACCOUNT_ID, &mut resp).unwrap();
        })
    });
    group.finish();
}

fn bench_registration_finalize(c: &mut Criterion) {
    let responder = OpaqueResponder::generate().unwrap();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(&responder, &serialize_req(&req), ACCOUNT_ID, &mut resp).unwrap();

    let mut group = c.benchmark_group("registration");
    group.sample_size(10);
    group.bench_function("finalize", |b| {
        b.iter_batched(
            || {
                let mut s = InitiatorState::new();
                let mut r = RegistrationRequest::new();
                create_registration_request(PASSWORD, &mut r, &mut s).unwrap();
                let mut rsp = RegistrationResponse::new();
                create_registration_response(&responder, &serialize_req(&r), ACCOUNT_ID, &mut rsp)
                    .unwrap();
                (s, rsp)
            },
            |(mut s, rsp)| {
                let mut record = RegistrationRecord::new();
                finalize_registration(&initiator, &serialize_resp(&rsp), &mut s, &mut record)
                    .unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_auth_ke1(c: &mut Criterion) {
    let mut group = c.benchmark_group("authentication");
    group.bench_function("generate_ke1", |b| {
        b.iter(|| {
            let mut state = InitiatorState::new();
            let mut ke1 = Ke1Message::new();
            generate_ke1(PASSWORD, ACCOUNT_ID, &mut ke1, &mut state).unwrap();
        })
    });
    group.finish();
}

fn bench_auth_ke2(c: &mut Criterion) {
    let (responder, record_bytes) = setup_registered();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(PASSWORD, ACCOUNT_ID, &mut ke1, &mut client_state).unwrap();

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )
    .unwrap();

    let mut credentials = ResponderCredentials::new();
    build_credentials(&record_bytes, &mut credentials).unwrap();

    let mut group = c.benchmark_group("authentication");
    group.bench_function("generate_ke2", |b| {
        b.iter_batched(
            || {
                let mut cs = InitiatorState::new();
                let mut k1 = Ke1Message::new();
                generate_ke1(PASSWORD, ACCOUNT_ID, &mut k1, &mut cs).unwrap();
                let mut k1b = vec![0u8; KE1_LENGTH];
                protocol::write_ke1(
                    &k1.credential_request,
                    &k1.initiator_public_key,
                    &k1.initiator_nonce,
                    &k1.pq_ephemeral_public_key,
                    &mut k1b,
                )
                .unwrap();
                k1b
            },
            |k1b| {
                let mut server_state = ResponderState::new();
                let mut ke2 = Ke2Message::new();
                generate_ke2(
                    &responder,
                    &k1b,
                    ACCOUNT_ID,
                    &credentials,
                    &mut ke2,
                    &mut server_state,
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_auth_ke3(c: &mut Criterion) {
    let (responder, record_bytes) = setup_registered();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut credentials = ResponderCredentials::new();
    build_credentials(&record_bytes, &mut credentials).unwrap();

    let mut group = c.benchmark_group("authentication");
    group.sample_size(10);
    group.bench_function("generate_ke3", |b| {
        b.iter_batched(
            || {
                let mut cs = InitiatorState::new();
                let mut k1 = Ke1Message::new();
                generate_ke1(PASSWORD, ACCOUNT_ID, &mut k1, &mut cs).unwrap();
                let mut k1b = vec![0u8; KE1_LENGTH];
                protocol::write_ke1(
                    &k1.credential_request,
                    &k1.initiator_public_key,
                    &k1.initiator_nonce,
                    &k1.pq_ephemeral_public_key,
                    &mut k1b,
                )
                .unwrap();

                let mut ss = ResponderState::new();
                let mut k2 = Ke2Message::new();
                generate_ke2(&responder, &k1b, ACCOUNT_ID, &credentials, &mut k2, &mut ss).unwrap();
                let mut k2b = vec![0u8; KE2_LENGTH];
                protocol::write_ke2(
                    &k2.responder_nonce,
                    &k2.responder_public_key,
                    &k2.credential_response,
                    &k2.responder_mac,
                    &k2.kem_ciphertext,
                    &mut k2b,
                )
                .unwrap();
                (cs, k2b)
            },
            |(mut cs, k2b)| {
                let mut ke3 = Ke3Message::new();
                generate_ke3(&initiator, &k2b, &mut cs, &mut ke3).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_auth_finish(c: &mut Criterion) {
    let (responder, record_bytes) = setup_registered();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut credentials = ResponderCredentials::new();
    build_credentials(&record_bytes, &mut credentials).unwrap();

    let mut group = c.benchmark_group("authentication");
    group.bench_function("responder_finish", |b| {
        b.iter_batched(
            || {
                let mut cs = InitiatorState::new();
                let mut k1 = Ke1Message::new();
                generate_ke1(PASSWORD, ACCOUNT_ID, &mut k1, &mut cs).unwrap();
                let mut k1b = vec![0u8; KE1_LENGTH];
                protocol::write_ke1(
                    &k1.credential_request,
                    &k1.initiator_public_key,
                    &k1.initiator_nonce,
                    &k1.pq_ephemeral_public_key,
                    &mut k1b,
                )
                .unwrap();

                let mut ss = ResponderState::new();
                let mut k2 = Ke2Message::new();
                generate_ke2(&responder, &k1b, ACCOUNT_ID, &credentials, &mut k2, &mut ss).unwrap();
                let mut k2b = vec![0u8; KE2_LENGTH];
                protocol::write_ke2(
                    &k2.responder_nonce,
                    &k2.responder_public_key,
                    &k2.credential_response,
                    &k2.responder_mac,
                    &k2.kem_ciphertext,
                    &mut k2b,
                )
                .unwrap();

                let mut ke3 = Ke3Message::new();
                generate_ke3(&initiator, &k2b, &mut cs, &mut ke3).unwrap();
                let mut k3b = vec![0u8; KE3_LENGTH];
                protocol::write_ke3(&ke3.initiator_mac, &mut k3b).unwrap();

                (ss, k3b)
            },
            |(mut ss, k3b)| {
                let mut sk = [0u8; HASH_LENGTH];
                let mut mk = [0u8; MASTER_KEY_LENGTH];
                responder_finish(&k3b, &mut ss, &mut sk, &mut mk).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn bench_full_authentication(c: &mut Criterion) {
    let (responder, record_bytes) = setup_registered();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut credentials = ResponderCredentials::new();
    build_credentials(&record_bytes, &mut credentials).unwrap();

    let mut group = c.benchmark_group("full_protocol");
    group.sample_size(10);
    group.bench_function("authentication_e2e", |b| {
        b.iter(|| {
            let mut cs = InitiatorState::new();
            let mut k1 = Ke1Message::new();
            generate_ke1(PASSWORD, ACCOUNT_ID, &mut k1, &mut cs).unwrap();
            let mut k1b = vec![0u8; KE1_LENGTH];
            protocol::write_ke1(
                &k1.credential_request,
                &k1.initiator_public_key,
                &k1.initiator_nonce,
                &k1.pq_ephemeral_public_key,
                &mut k1b,
            )
            .unwrap();

            let mut ss = ResponderState::new();
            let mut k2 = Ke2Message::new();
            generate_ke2(&responder, &k1b, ACCOUNT_ID, &credentials, &mut k2, &mut ss).unwrap();
            let mut k2b = vec![0u8; KE2_LENGTH];
            protocol::write_ke2(
                &k2.responder_nonce,
                &k2.responder_public_key,
                &k2.credential_response,
                &k2.responder_mac,
                &k2.kem_ciphertext,
                &mut k2b,
            )
            .unwrap();

            let mut ke3 = Ke3Message::new();
            generate_ke3(&initiator, &k2b, &mut cs, &mut ke3).unwrap();
            let mut k3b = vec![0u8; KE3_LENGTH];
            protocol::write_ke3(&ke3.initiator_mac, &mut k3b).unwrap();

            let mut server_sk = [0u8; HASH_LENGTH];
            let mut server_mk = [0u8; MASTER_KEY_LENGTH];
            responder_finish(&k3b, &mut ss, &mut server_sk, &mut server_mk).unwrap();

            let mut client_sk = [0u8; HASH_LENGTH];
            let mut client_mk = [0u8; MASTER_KEY_LENGTH];
            initiator_finish(&mut cs, &mut client_sk, &mut client_mk).unwrap();
        })
    });
    group.finish();
}

fn bench_ke3_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("ke3_primitives");
    group.sample_size(30);

    group.bench_function("pq_decapsulate_only", |b| {
        b.iter_batched(
            || {
                let mut pk = [0u8; pq::KEM_PUBLIC_KEY_LENGTH];
                let mut sk = [0u8; pq::KEM_SECRET_KEY_LENGTH];
                pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();
                let mut ct = [0u8; pq::KEM_CIPHERTEXT_LENGTH];
                let mut ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
                pq_kem::encapsulate(&pk, &mut ct, &mut ss).unwrap();
                (sk, ct)
            },
            |(sk, ct)| {
                let mut out = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
                pq_kem::decapsulate(&sk, &ct, &mut out).unwrap();
                criterion::black_box(out);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("ristretto_4dh_only", |b| {
        b.iter_batched(
            || {
                let sk1 = crypto::random_nonzero_scalar().unwrap();
                let sk2 = crypto::random_nonzero_scalar().unwrap();
                let pk1 = crypto::scalarmult_base(&sk1).unwrap();
                let pk2 = crypto::scalarmult_base(&sk2).unwrap();
                (sk1, sk2, pk1, pk2)
            },
            |(sk1, sk2, pk1, pk2)| {
                let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
                let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
                let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
                let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
                crypto::scalar_mult(&sk1, &pk1, &mut dh1).unwrap();
                crypto::scalar_mult(&sk1, &pk2, &mut dh2).unwrap();
                crypto::scalar_mult(&sk2, &pk1, &mut dh3).unwrap();
                crypto::scalar_mult(&sk2, &pk2, &mut dh4).unwrap();
                criterion::black_box((dh1, dh2, dh3, dh4));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.bench_function("hkdf_mac_transcript_only", |b| {
        b.iter_batched(
            || {
                let mut classical_ikm = [0u8; CLASSICAL_IKM_LENGTH];
                let mut pq_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
                let mut transcript_hash = [0u8; HASH_LENGTH];
                crypto::random_bytes(&mut classical_ikm).unwrap();
                crypto::random_bytes(&mut pq_ss).unwrap();
                crypto::random_bytes(&mut transcript_hash).unwrap();

                let transcript_input_size = 2 * NONCE_LENGTH
                    + DH_COMPONENT_COUNT * PUBLIC_KEY_LENGTH
                    + CREDENTIAL_RESPONSE_LENGTH
                    + pq::KEM_CIPHERTEXT_LENGTH
                    + pq::KEM_PUBLIC_KEY_LENGTH
                    + HASH_LENGTH;
                let mut transcript_input = vec![0u8; transcript_input_size];
                crypto::random_bytes(&mut transcript_input).unwrap();
                (classical_ikm, pq_ss, transcript_hash, transcript_input)
            },
            |(classical_ikm, pq_ss, transcript_hash, transcript_input)| {
                let mut prk = [0u8; HASH_LENGTH];
                pq_kem::combine_key_material(&classical_ikm, &pq_ss, &transcript_hash, &mut prk)
                    .unwrap();

                let mut session_key = [0u8; HASH_LENGTH];
                crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)
                    .unwrap();
                let mut master_key = [0u8; MASTER_KEY_LENGTH];
                crypto::key_derivation_expand(&prk, pq_labels::PQ_MASTER_KEY_INFO, &mut master_key)
                    .unwrap();

                let mut responder_mac_key = [0u8; MAC_LENGTH];
                crypto::key_derivation_expand(
                    &prk,
                    pq_labels::PQ_RESPONDER_MAC_INFO,
                    &mut responder_mac_key,
                )
                .unwrap();
                let mut initiator_mac_key = [0u8; MAC_LENGTH];
                crypto::key_derivation_expand(
                    &prk,
                    pq_labels::PQ_INITIATOR_MAC_INFO,
                    &mut initiator_mac_key,
                )
                .unwrap();

                let mut responder_mac = [0u8; MAC_LENGTH];
                let mut initiator_mac = [0u8; MAC_LENGTH];
                crypto::hmac_sha512(&responder_mac_key, &transcript_input, &mut responder_mac)
                    .unwrap();
                crypto::hmac_sha512(&initiator_mac_key, &transcript_input, &mut initiator_mac)
                    .unwrap();

                criterion::black_box((
                    session_key,
                    master_key,
                    responder_mac,
                    initiator_mac,
                ));
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    registration,
    bench_registration_request,
    bench_registration_response,
    bench_registration_finalize,
);
criterion_group!(
    authentication,
    bench_auth_ke1,
    bench_auth_ke2,
    bench_auth_ke3,
    bench_auth_finish,
);
criterion_group!(full, bench_full_authentication,);
criterion_group!(primitives, bench_ke3_primitives,);
criterion_main!(registration, authentication, full, primitives);
