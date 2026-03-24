// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{criterion_group, criterion_main, Criterion};
use opaque_agent::*;
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
criterion_main!(registration, authentication, full);
