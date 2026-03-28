// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use opaque_agent::*;
use opaque_core::protocol;
use opaque_core::types::*;
use opaque_relay::*;

const ACCOUNT_ID: &[u8] = b"throughput@example.com";
const PASSWORD: &[u8] = b"throughput benchmark password";

fn setup() -> (OpaqueResponder, Vec<u8>, ResponderCredentials) {
    let responder = OpaqueResponder::generate().unwrap();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

    let mut req_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
    protocol::write_registration_request(&req.data, &mut req_wire).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(&responder, &req_wire, ACCOUNT_ID, &mut resp).unwrap();

    let mut resp_wire = vec![0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
    protocol::write_registration_response(
        &resp.data[..PUBLIC_KEY_LENGTH],
        &resp.data[PUBLIC_KEY_LENGTH..],
        &mut resp_wire,
    )
    .unwrap();

    let mut record = RegistrationRecord::new();
    finalize_registration(&initiator, &resp_wire, &mut state, &mut record).unwrap();

    let mut record_bytes = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(
        &record.envelope,
        &record.initiator_public_key,
        &mut record_bytes,
    )
    .unwrap();

    let mut creds = ResponderCredentials::new();
    build_credentials(&record_bytes, &mut creds).unwrap();

    (responder, record_bytes, creds)
}

fn make_ke1_bytes() -> (InitiatorState, Vec<u8>) {
    let mut state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(PASSWORD, ACCOUNT_ID, &mut ke1, &mut state).unwrap();

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )
    .unwrap();

    (state, ke1_bytes)
}

fn bench_relay_finish_only(c: &mut Criterion) {
    let (responder, _, credentials) = setup();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut group = c.benchmark_group("relay_throughput");
    group.throughput(Throughput::Elements(1));
    group.sample_size(50);

    group.bench_function("finish_only", |b| {
        b.iter_batched(
            || {
                let (mut cs, ke1_bytes) = make_ke1_bytes();

                let mut ss = ResponderState::new();
                let mut k2 = Ke2Message::new();
                generate_ke2(
                    &responder,
                    &ke1_bytes,
                    ACCOUNT_ID,
                    &credentials,
                    &mut k2,
                    &mut ss,
                )
                .unwrap();

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
            |(mut ss, ke3_bytes)| {
                let mut sk = [0u8; HASH_LENGTH];
                let mut mk = [0u8; MASTER_KEY_LENGTH];
                responder_finish(
                    black_box(&ke3_bytes),
                    black_box(&mut ss),
                    black_box(&mut sk),
                    black_box(&mut mk),
                )
                .unwrap();
                black_box(sk);
                black_box(mk);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_relay_ke2_only(c: &mut Criterion) {
    let (responder, _, credentials) = setup();

    let ke1_batch: Vec<Vec<u8>> = (0..100).map(|_| make_ke1_bytes().1).collect();

    let mut group = c.benchmark_group("relay_throughput");
    group.throughput(Throughput::Elements(1));

    group.bench_function("ke2_only", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let ke1_bytes = &ke1_batch[idx % ke1_batch.len()];
            idx += 1;

            let mut ss = ResponderState::new();
            let mut k2 = Ke2Message::new();
            generate_ke2(
                black_box(&responder),
                black_box(ke1_bytes),
                black_box(ACCOUNT_ID),
                black_box(&credentials),
                black_box(&mut k2),
                black_box(&mut ss),
            )
            .unwrap();
            black_box(k2.responder_mac);
        })
    });

    group.finish();
}

fn bench_client_ke3_only(c: &mut Criterion) {
    let (responder, _, credentials) = setup();
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut group = c.benchmark_group("relay_throughput");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);

    group.bench_function("ke3_only", |b| {
        b.iter_batched(
            || {
                let (cs, ke1_bytes) = make_ke1_bytes();
                let mut ss = ResponderState::new();
                let mut k2 = Ke2Message::new();
                generate_ke2(
                    &responder,
                    &ke1_bytes,
                    ACCOUNT_ID,
                    &credentials,
                    &mut k2,
                    &mut ss,
                )
                .unwrap();
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
                generate_ke3(
                    black_box(&initiator),
                    black_box(&k2b),
                    black_box(&mut cs),
                    black_box(&mut ke3),
                )
                .unwrap();
                black_box(ke3.initiator_mac);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(
    throughput,
    bench_relay_ke2_only,
    bench_client_ke3_only,
    bench_relay_finish_only,
);
criterion_main!(throughput);
