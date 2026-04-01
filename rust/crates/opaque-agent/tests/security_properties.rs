// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

#![allow(dead_code)]

use opaque_agent::*;
use opaque_core::types::*;
use opaque_core::{crypto, oprf, pq_kem, protocol};
use opaque_relay::*;

const ACCOUNT_ID: &[u8] = b"alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn register(password: &[u8], responder: &OpaqueResponder) -> Vec<u8> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(password, &mut req, &mut state).unwrap();

    let mut req_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
    protocol::write_registration_request(&req.data, &mut req_wire).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(responder, &req_wire, ACCOUNT_ID, &mut resp).unwrap();

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
    record_bytes
}

fn authenticate(
    password: &[u8],
    responder: &OpaqueResponder,
    record_bytes: &[u8],
) -> (
    [u8; HASH_LENGTH],
    [u8; MASTER_KEY_LENGTH],
    [u8; HASH_LENGTH],
    [u8; MASTER_KEY_LENGTH],
) {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(password, ACCOUNT_ID, &mut ke1, &mut client_state).unwrap();

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
    build_credentials(record_bytes, &mut credentials).unwrap();

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &credentials,
        &mut ke2,
        &mut server_state,
    )
    .unwrap();

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )
    .unwrap();

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).unwrap();

    let mut ke3_bytes = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes).unwrap();

    let mut s_sk = [0u8; HASH_LENGTH];
    let mut s_mk = [0u8; MASTER_KEY_LENGTH];
    responder_finish(&ke3_bytes, &mut server_state, &mut s_sk, &mut s_mk).unwrap();

    let mut c_sk = [0u8; HASH_LENGTH];
    let mut c_mk = [0u8; MASTER_KEY_LENGTH];
    initiator_finish(&mut client_state, &mut c_sk, &mut c_mk).unwrap();

    (c_sk, c_mk, s_sk, s_mk)
}

struct InterceptedSession {
    ke1_bytes: Vec<u8>,
    ke2_bytes: Vec<u8>,
    ke3_bytes: Vec<u8>,
    client_ephemeral_sk: [u8; PRIVATE_KEY_LENGTH],
    client_ephemeral_pk: [u8; PUBLIC_KEY_LENGTH],
    client_static_sk: [u8; PRIVATE_KEY_LENGTH],
    client_static_pk: [u8; PUBLIC_KEY_LENGTH],
    client_nonce: [u8; NONCE_LENGTH],
    client_kem_pk: [u8; pq::KEM_PUBLIC_KEY_LENGTH],
    client_kem_sk: [u8; pq::KEM_SECRET_KEY_LENGTH],
    client_kem_ss: [u8; pq::KEM_SHARED_SECRET_LENGTH],
    server_ephemeral_sk: [u8; PRIVATE_KEY_LENGTH],
    server_ephemeral_pk: [u8; PUBLIC_KEY_LENGTH],
    server_static_sk: [u8; PRIVATE_KEY_LENGTH],
    server_static_pk: [u8; PUBLIC_KEY_LENGTH],
    server_nonce: [u8; NONCE_LENGTH],
    server_kem_ss: [u8; pq::KEM_SHARED_SECRET_LENGTH],
    credential_response: [u8; CREDENTIAL_RESPONSE_LENGTH],
    kem_ciphertext: [u8; pq::KEM_CIPHERTEXT_LENGTH],
    client_session_key: [u8; HASH_LENGTH],
    server_session_key: [u8; HASH_LENGTH],
}

fn intercepted_authenticate(
    password: &[u8],
    responder: &OpaqueResponder,
    record_bytes: &[u8],
) -> InterceptedSession {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(password, ACCOUNT_ID, &mut ke1, &mut client_state).unwrap();

    let client_ephemeral_sk = *client_state.initiator_ephemeral_private_key();
    let client_ephemeral_pk = *client_state.initiator_ephemeral_public_key();
    let client_nonce = *client_state.initiator_nonce();
    let client_kem_pk = *client_state.pq_ephemeral_public_key();
    let client_kem_sk = *client_state.pq_ephemeral_secret_key();

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
    build_credentials(record_bytes, &mut credentials).unwrap();

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &credentials,
        &mut ke2,
        &mut server_state,
    )
    .unwrap();

    let server_ephemeral_sk = *server_state.responder_ephemeral_private_key();
    let server_ephemeral_pk = *server_state.responder_ephemeral_public_key();
    let server_nonce = ke2.responder_nonce;
    let server_kem_ss = *server_state.pq_shared_secret();
    let credential_response = ke2.credential_response;
    let kem_ciphertext = ke2.kem_ciphertext;

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )
    .unwrap();

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).unwrap();

    let client_static_sk = *client_state.initiator_private_key();
    let client_static_pk = *client_state.initiator_public_key();
    let client_kem_ss = *client_state.pq_shared_secret();

    let mut ke3_bytes = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes).unwrap();

    let mut s_sk = [0u8; HASH_LENGTH];
    let mut s_mk = [0u8; MASTER_KEY_LENGTH];
    responder_finish(&ke3_bytes, &mut server_state, &mut s_sk, &mut s_mk).unwrap();

    let mut c_sk = [0u8; HASH_LENGTH];
    let mut c_mk = [0u8; MASTER_KEY_LENGTH];
    initiator_finish(&mut client_state, &mut c_sk, &mut c_mk).unwrap();

    InterceptedSession {
        ke1_bytes,
        ke2_bytes,
        ke3_bytes,
        client_ephemeral_sk,
        client_ephemeral_pk,
        client_static_sk,
        client_static_pk,
        client_nonce,
        client_kem_pk,
        client_kem_sk,
        client_kem_ss,
        server_ephemeral_sk,
        server_ephemeral_pk,
        server_static_sk: responder.keypair().private_key,
        server_static_pk: responder.keypair().public_key,
        server_nonce,
        server_kem_ss,
        credential_response,
        kem_ciphertext,
        client_session_key: c_sk,
        server_session_key: s_sk,
    }
}

fn adversary_derive_session_key(
    dh1: &[u8; PUBLIC_KEY_LENGTH],
    dh2: &[u8; PUBLIC_KEY_LENGTH],
    dh3: &[u8; PUBLIC_KEY_LENGTH],
    dh4: &[u8; PUBLIC_KEY_LENGTH],
    kem_ss: &[u8],
    session: &InterceptedSession,
) -> [u8; HASH_LENGTH] {
    let mut account_context_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::ACCOUNT_CONTEXT_BINDING, ACCOUNT_ID],
        &mut account_context_hash,
    );
    let mac_input_size = 2 * NONCE_LENGTH
        + 4 * PUBLIC_KEY_LENGTH
        + CREDENTIAL_RESPONSE_LENGTH
        + pq::KEM_CIPHERTEXT_LENGTH
        + pq::KEM_PUBLIC_KEY_LENGTH
        + HASH_LENGTH;
    let mut mac_input = vec![0u8; mac_input_size];
    let mut off = 0;
    let mut append = |data: &[u8]| {
        mac_input[off..off + data.len()].copy_from_slice(data);
        off += data.len();
    };
    append(&session.client_ephemeral_pk);
    append(&session.server_ephemeral_pk);
    append(&session.client_nonce);
    append(&session.server_nonce);
    append(&session.client_static_pk);
    append(&session.server_static_pk);
    append(&session.credential_response);
    append(&session.client_kem_pk);
    append(&session.kem_ciphertext);
    append(&account_context_hash);

    let mut transcript_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::TRANSCRIPT_CONTEXT, &mac_input],
        &mut transcript_hash,
    );

    let mut classical_ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
    classical_ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(dh1);
    classical_ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(dh2);
    classical_ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(dh3);
    classical_ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(dh4);

    let mut prk = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, kem_ss, &transcript_hash, &mut prk).unwrap();

    let mut session_key = [0u8; HASH_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key).unwrap();

    session_key
}

fn setup() -> (OpaqueResponder, Vec<u8>) {
    let responder = OpaqueResponder::generate().unwrap();
    let record = register(PASSWORD, &responder);
    (responder, record)
}

mod p1_session_key_secrecy {
    use super::*;

    #[test]
    fn session_keys_match_and_nonzero() {
        let (responder, record) = setup();
        let (c_sk, c_mk, s_sk, s_mk) = authenticate(PASSWORD, &responder, &record);

        assert_eq!(c_sk, s_sk, "session keys must match");
        assert_eq!(c_mk, s_mk, "master keys must match");
        assert_eq!(c_sk.len(), HASH_LENGTH);
        assert!(!c_sk.iter().all(|&b| b == 0));
        assert!(!c_mk.iter().all(|&b| b == 0));
    }

    #[test]
    fn session_key_not_derivable_from_public_transcript() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let zero_dh = [0u8; PUBLIC_KEY_LENGTH];
        let zero_kem = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let derived = adversary_derive_session_key(
            &zero_dh, &zero_dh, &zero_dh, &zero_dh, &zero_kem, &session,
        );
        assert_ne!(derived, session.client_session_key);
    }

    #[test]
    fn different_sessions_independent_keys() {
        let (responder, record) = setup();
        let (sk1, _, _, _) = authenticate(PASSWORD, &responder, &record);
        let (sk2, _, _, _) = authenticate(PASSWORD, &responder, &record);
        assert_ne!(sk1, sk2, "different sessions must produce different keys");
    }

    #[test]
    fn session_key_entropy() {
        let (responder, record) = setup();
        let mut keys = std::collections::HashSet::new();
        for _ in 0..10 {
            let (sk, _, _, _) = authenticate(PASSWORD, &responder, &record);
            keys.insert(sk);
        }
        assert_eq!(keys.len(), 10, "all 10 session keys must be unique");
    }
}

mod p2_password_secrecy {
    use super::*;

    fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn password_not_in_registration_messages() {
        let responder = OpaqueResponder::generate().unwrap();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

        let mut state = InitiatorState::new();
        let mut req = RegistrationRequest::new();
        create_registration_request(PASSWORD, &mut req, &mut state).unwrap();
        assert!(!contains_subsequence(&req.data, PASSWORD));

        let mut req_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
        protocol::write_registration_request(&req.data, &mut req_wire).unwrap();

        let mut resp = RegistrationResponse::new();
        create_registration_response(&responder, &req_wire, ACCOUNT_ID, &mut resp).unwrap();
        assert!(!contains_subsequence(&resp.data, PASSWORD));

        let mut resp_wire = vec![0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
        protocol::write_registration_response(
            &resp.data[..PUBLIC_KEY_LENGTH],
            &resp.data[PUBLIC_KEY_LENGTH..],
            &mut resp_wire,
        )
        .unwrap();

        let mut record = RegistrationRecord::new();
        finalize_registration(&initiator, &resp_wire, &mut state, &mut record).unwrap();
        assert!(!contains_subsequence(&record.envelope, PASSWORD));

        let mut record_bytes = vec![0u8; REGISTRATION_RECORD_LENGTH];
        protocol::write_registration_record(
            &record.envelope,
            &record.initiator_public_key,
            &mut record_bytes,
        )
        .unwrap();
        assert!(!contains_subsequence(&record_bytes, PASSWORD));
    }

    #[test]
    fn password_not_in_ke1() {
        let (responder, record) = setup();
        let _initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
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

        assert!(!contains_subsequence(&ke1_bytes, PASSWORD));
        let _ = record;
    }

    #[test]
    fn password_not_in_ke2_ke3() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);
        assert!(!contains_subsequence(&session.ke2_bytes, PASSWORD));
        assert!(!contains_subsequence(&session.ke3_bytes, PASSWORD));
    }

    #[test]
    fn oprf_blinds_password_from_server() {
        let mut blinded1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind1 = [0u8; PRIVATE_KEY_LENGTH];
        let mut blinded2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind2 = [0u8; PRIVATE_KEY_LENGTH];

        oprf::blind(PASSWORD, &mut blinded1, &mut blind1).unwrap();
        oprf::blind(PASSWORD, &mut blinded2, &mut blind2).unwrap();

        assert_ne!(blinded1, blinded2);
        crypto::validate_ristretto_point(&blinded1).unwrap();
        crypto::validate_ristretto_point(&blinded2).unwrap();
    }

    #[test]
    fn different_passwords_different_oprf_outputs() {
        let oprf_key = crypto::random_nonzero_scalar().unwrap();

        let compute_oprf = |pwd: &[u8]| -> [u8; HASH_LENGTH] {
            let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
            let mut blind = [0u8; PRIVATE_KEY_LENGTH];
            oprf::blind(pwd, &mut blinded, &mut blind).unwrap();

            let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
            oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();

            let mut output = [0u8; HASH_LENGTH];
            oprf::finalize(pwd, &blind, &evaluated, &mut output).unwrap();
            output
        };

        let out1 = compute_oprf(b"password1");
        let out2 = compute_oprf(b"password2");
        assert_ne!(out1, out2);
    }

    #[test]
    fn record_reveals_no_password_material() {
        let responder = OpaqueResponder::generate().unwrap();

        let passwords: Vec<&[u8]> = vec![
            b"alpha", b"bravo", b"charlie", b"delta", b"echo", b"foxtrot", b"golf", b"hotel",
            b"india", b"juliet",
        ];

        let records: Vec<Vec<u8>> = passwords.iter().map(|p| register(p, &responder)).collect();

        for i in 0..records.len() {
            for j in (i + 1)..records.len() {
                assert_ne!(
                    records[i], records[j],
                    "records for different passwords must differ"
                );
            }
        }

        for (pwd, rec) in passwords.iter().zip(records.iter()) {
            assert!(!contains_subsequence(rec, pwd));
        }
    }
}

mod p3_classical_forward_secrecy {
    use super::*;

    #[test]
    fn forward_secrecy_server_ltk_compromise() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let server_sk = &session.server_static_sk;
        let client_static_pk = &session.client_static_pk;
        let client_eph_pk = &session.client_ephemeral_pk;

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(server_sk, client_static_pk, &mut dh1).unwrap();
        crypto::scalar_mult(server_sk, client_eph_pk, &mut dh2).unwrap();

        let fake_dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let fake_dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let fake_kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];

        let derived =
            adversary_derive_session_key(&dh1, &dh2, &fake_dh3, &fake_dh4, &fake_kem_ss, &session);
        assert_ne!(derived, session.client_session_key);
    }

    #[test]
    fn forward_secrecy_full_ltk_compromise() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let server_sk = &session.server_static_sk;
        let client_sk = &session.client_static_sk;

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(client_sk, &session.server_static_pk, &mut dh1).unwrap();

        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(client_sk, &session.server_ephemeral_pk, &mut dh3).unwrap();

        let fake_dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let fake_dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let fake_kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];

        let derived =
            adversary_derive_session_key(&dh1, &fake_dh2, &dh3, &fake_dh4, &fake_kem_ss, &session);
        assert_ne!(derived, session.client_session_key);

        let mut dh2_server = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(server_sk, &session.client_ephemeral_pk, &mut dh2_server).unwrap();
        let fake_dh3 = [0u8; PUBLIC_KEY_LENGTH];
        let derived2 = adversary_derive_session_key(
            &dh1,
            &dh2_server,
            &fake_dh3,
            &fake_dh4,
            &fake_kem_ss,
            &session,
        );
        assert_ne!(derived2, session.client_session_key);
    }

    #[test]
    fn ephemeral_keys_fresh_per_session() {
        let (responder, record) = setup();
        let s1 = intercepted_authenticate(PASSWORD, &responder, &record);
        let s2 = intercepted_authenticate(PASSWORD, &responder, &record);

        assert_ne!(s1.client_ephemeral_sk, s2.client_ephemeral_sk);
        assert_ne!(s1.client_ephemeral_pk, s2.client_ephemeral_pk);
        assert_ne!(s1.server_ephemeral_sk, s2.server_ephemeral_sk);
        assert_ne!(s1.server_ephemeral_pk, s2.server_ephemeral_pk);
        assert_ne!(s1.client_kem_pk, s2.client_kem_pk);
        assert_ne!(s1.client_kem_sk, s2.client_kem_sk);
        assert_ne!(s1.client_nonce, s2.client_nonce);
        assert_ne!(s1.server_nonce, s2.server_nonce);
    }
}

mod p4_pq_forward_secrecy {
    use super::*;

    #[test]
    fn quantum_dh_broken_kem_intact() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_static_pk,
            &mut dh1,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_static_pk,
            &mut dh2,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_ephemeral_pk,
            &mut dh3,
        )
        .unwrap();

        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_ephemeral_pk,
            &mut dh4,
        )
        .unwrap();

        let fake_kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let derived = adversary_derive_session_key(&dh1, &dh2, &dh3, &dh4, &fake_kem_ss, &session);
        assert_ne!(
            derived, session.client_session_key,
            "quantum DH break alone must NOT reveal session key"
        );

        let mut random_kem = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        crypto::random_bytes(&mut random_kem).unwrap();
        let derived2 = adversary_derive_session_key(&dh1, &dh2, &dh3, &dh4, &random_kem, &session);
        assert_ne!(derived2, session.client_session_key);
    }

    #[test]
    fn kem_shared_secret_not_in_ciphertext() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
            haystack.windows(needle.len()).any(|w| w == needle)
        }
        assert!(!contains_subsequence(
            &session.kem_ciphertext,
            &session.client_kem_ss
        ));

        let mut wrong_pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
        let mut wrong_sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
        pq_kem::keypair_generate(&mut wrong_pk, &mut wrong_sk).unwrap();

        let mut wrong_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        pq_kem::decapsulate(&wrong_sk, &session.kem_ciphertext, &mut wrong_ss).unwrap();
        assert_ne!(&wrong_ss[..], &session.client_kem_ss[..]);
    }

    #[test]
    fn full_dh_compromise_plus_ltk_kem_protects() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.server_static_sk,
            &session.client_static_pk,
            &mut dh1,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.server_static_sk,
            &session.client_ephemeral_pk,
            &mut dh2,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.server_ephemeral_sk,
            &session.client_static_pk,
            &mut dh3,
        )
        .unwrap();

        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.server_ephemeral_sk,
            &session.client_ephemeral_pk,
            &mut dh4,
        )
        .unwrap();

        let mut bad_kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        crypto::random_bytes(&mut bad_kem_ss).unwrap();

        let derived = adversary_derive_session_key(&dh1, &dh2, &dh3, &dh4, &bad_kem_ss, &session);
        assert_ne!(
            derived, session.client_session_key,
            "full DH compromise with unknown KEM ss must NOT break session key"
        );
    }
}

mod p5_mutual_authentication {
    use super::*;

    #[test]
    fn client_rejects_forged_ke2_wrong_server() {
        let server_a = OpaqueResponder::generate().unwrap();
        let record = register(PASSWORD, &server_a);

        let server_b = OpaqueResponder::generate().unwrap();

        let initiator = OpaqueInitiator::new(server_a.public_key()).unwrap();
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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &server_b,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        let mut ke2_bytes = vec![0u8; KE2_LENGTH];
        protocol::write_ke2(
            &ke2.responder_nonce,
            &ke2.responder_public_key,
            &ke2.credential_response,
            &ke2.responder_mac,
            &ke2.kem_ciphertext,
            &mut ke2_bytes,
        )
        .unwrap();

        let mut ke3 = Ke3Message::new();
        let result = generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3);
        assert!(result.is_err(), "wrong server must be rejected");
    }

    #[test]
    fn client_rejects_tampered_ke2_mac() {
        let (responder, record) = setup();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        ke2.responder_mac[0] ^= 0xFF;

        let mut ke2_bytes = vec![0u8; KE2_LENGTH];
        protocol::write_ke2(
            &ke2.responder_nonce,
            &ke2.responder_public_key,
            &ke2.credential_response,
            &ke2.responder_mac,
            &ke2.kem_ciphertext,
            &mut ke2_bytes,
        )
        .unwrap();

        let mut ke3 = Ke3Message::new();
        assert!(
            generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).is_err(),
            "tampered MAC must be rejected"
        );
    }

    #[test]
    fn client_rejects_tampered_ke2_nonce() {
        let (responder, record) = setup();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        let mut ke2_bytes = vec![0u8; KE2_LENGTH];
        ke2.responder_nonce[0] ^= 0xFF;
        protocol::write_ke2(
            &ke2.responder_nonce,
            &ke2.responder_public_key,
            &ke2.credential_response,
            &ke2.responder_mac,
            &ke2.kem_ciphertext,
            &mut ke2_bytes,
        )
        .unwrap();

        let mut ke3 = Ke3Message::new();
        assert!(
            generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).is_err(),
            "tampered nonce must cause MAC mismatch"
        );
    }

    #[test]
    fn client_rejects_tampered_kem_ciphertext() {
        let (responder, record) = setup();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        ke2.kem_ciphertext[0] ^= 0xFF;

        let mut ke2_bytes = vec![0u8; KE2_LENGTH];
        protocol::write_ke2(
            &ke2.responder_nonce,
            &ke2.responder_public_key,
            &ke2.credential_response,
            &ke2.responder_mac,
            &ke2.kem_ciphertext,
            &mut ke2_bytes,
        )
        .unwrap();

        let mut ke3 = Ke3Message::new();
        assert!(
            generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).is_err(),
            "tampered KEM ciphertext must cause MAC mismatch"
        );
    }

    #[test]
    fn server_rejects_forged_ke3() {
        let (responder, record) = setup();
        let _initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        let mut fake_ke3 = vec![0u8; KE3_LENGTH];
        crypto::random_bytes(&mut fake_ke3).unwrap();

        let mut s_sk = [0u8; HASH_LENGTH];
        let mut s_mk = [0u8; MASTER_KEY_LENGTH];
        assert!(
            responder_finish(&fake_ke3, &mut server_state, &mut s_sk, &mut s_mk).is_err(),
            "forged KE3 must be rejected"
        );
    }

    #[test]
    fn server_rejects_tampered_ke3_mac() {
        let (responder, record) = setup();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

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
        build_credentials(&record, &mut credentials).unwrap();

        let mut server_state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            ACCOUNT_ID,
            &credentials,
            &mut ke2,
            &mut server_state,
        )
        .unwrap();

        let mut ke2_bytes = vec![0u8; KE2_LENGTH];
        protocol::write_ke2(
            &ke2.responder_nonce,
            &ke2.responder_public_key,
            &ke2.credential_response,
            &ke2.responder_mac,
            &ke2.kem_ciphertext,
            &mut ke2_bytes,
        )
        .unwrap();

        let mut ke3 = Ke3Message::new();
        generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).unwrap();

        ke3.initiator_mac[0] ^= 0xFF;
        let mut ke3_bytes = vec![0u8; KE3_LENGTH];
        protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes).unwrap();

        let mut s_sk = [0u8; HASH_LENGTH];
        let mut s_mk = [0u8; MASTER_KEY_LENGTH];
        assert!(
            responder_finish(&ke3_bytes, &mut server_state, &mut s_sk, &mut s_mk).is_err(),
            "tampered KE3 MAC must be rejected"
        );
    }

    #[test]
    fn replay_ke2_from_different_session_fails() {
        let (responder, record) = setup();

        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
        let mut cs1 = InitiatorState::new();
        let mut ke1_1 = Ke1Message::new();
        generate_ke1(PASSWORD, ACCOUNT_ID, &mut ke1_1, &mut cs1).unwrap();

        let mut ke1_bytes_1 = vec![0u8; KE1_LENGTH];
        protocol::write_ke1(
            &ke1_1.credential_request,
            &ke1_1.initiator_public_key,
            &ke1_1.initiator_nonce,
            &ke1_1.pq_ephemeral_public_key,
            &mut ke1_bytes_1,
        )
        .unwrap();

        let mut creds = ResponderCredentials::new();
        build_credentials(&record, &mut creds).unwrap();

        let mut ss1 = ResponderState::new();
        let mut ke2_1 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes_1,
            ACCOUNT_ID,
            &creds,
            &mut ke2_1,
            &mut ss1,
        )
        .unwrap();

        let mut ke2_bytes_1 = vec![0u8; KE2_LENGTH];
        protocol::write_ke2(
            &ke2_1.responder_nonce,
            &ke2_1.responder_public_key,
            &ke2_1.credential_response,
            &ke2_1.responder_mac,
            &ke2_1.kem_ciphertext,
            &mut ke2_bytes_1,
        )
        .unwrap();

        let mut cs2 = InitiatorState::new();
        let mut ke1_2 = Ke1Message::new();
        generate_ke1(PASSWORD, ACCOUNT_ID, &mut ke1_2, &mut cs2).unwrap();

        let mut ke3 = Ke3Message::new();
        let result = generate_ke3(&initiator, &ke2_bytes_1, &mut cs2, &mut ke3);
        assert!(
            result.is_err(),
            "replayed KE2 from different session must fail"
        );
    }

    #[test]
    fn session_key_agreement_injective() {
        let (responder, record) = setup();
        let mut keys = std::collections::HashSet::new();
        for _ in 0..5 {
            let (sk, _, _, _) = authenticate(PASSWORD, &responder, &record);
            assert!(keys.insert(sk), "each session must produce a unique key");
        }
    }
}

mod p6_and_model_hybrid_security {
    use super::*;

    #[test]
    fn dh_broken_only_insufficient() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_static_pk,
            &mut dh1,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_static_pk,
            &mut dh2,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_ephemeral_pk,
            &mut dh3,
        )
        .unwrap();
        let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_ephemeral_pk,
            &mut dh4,
        )
        .unwrap();

        let wrong_kem = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
        let derived = adversary_derive_session_key(&dh1, &dh2, &dh3, &dh4, &wrong_kem, &session);
        assert_ne!(
            derived, session.client_session_key,
            "DH-only break insufficient"
        );
    }

    #[test]
    fn kem_broken_only_insufficient() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let wrong_dh = [0u8; PUBLIC_KEY_LENGTH];
        let derived = adversary_derive_session_key(
            &wrong_dh,
            &wrong_dh,
            &wrong_dh,
            &wrong_dh,
            &session.client_kem_ss,
            &session,
        );
        assert_ne!(
            derived, session.client_session_key,
            "KEM-only break insufficient"
        );
    }

    #[test]
    fn both_broken_allows_recovery() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_static_pk,
            &mut dh1,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_static_pk,
            &mut dh2,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_ephemeral_pk,
            &mut dh3,
        )
        .unwrap();

        let mut dh4_both = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_ephemeral_sk,
            &session.server_ephemeral_pk,
            &mut dh4_both,
        )
        .unwrap();

        let derived = adversary_derive_session_key(
            &dh1,
            &dh2,
            &dh3,
            &dh4_both,
            &session.client_kem_ss,
            &session,
        );
        assert_eq!(
            derived, session.client_session_key,
            "with ALL secrets (4DH + KEM), adversary must recover session key (positive control)"
        );
    }

    #[test]
    fn partial_dh_insufficient() {
        let (responder, record) = setup();
        let session = intercepted_authenticate(PASSWORD, &responder, &record);

        let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
        let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_static_pk,
            &mut dh1,
        )
        .unwrap();
        crypto::scalar_mult(
            &session.client_static_sk,
            &session.server_ephemeral_pk,
            &mut dh3,
        )
        .unwrap();

        let wrong_dh2 = [0u8; PUBLIC_KEY_LENGTH];
        let wrong_dh4 = [0u8; PUBLIC_KEY_LENGTH];
        let derived = adversary_derive_session_key(
            &dh1,
            &wrong_dh2,
            &dh3,
            &wrong_dh4,
            &session.client_kem_ss,
            &session,
        );
        assert_ne!(
            derived, session.client_session_key,
            "partial DH compromise insufficient even with KEM ss"
        );
    }
}

mod p7_offline_dictionary_resistance {
    use super::*;

    #[test]
    fn envelope_not_decryptable_without_password() {
        let (_responder, record) = setup();
        let parsed = protocol::parse_registration_record(&record).unwrap();
        let envelope_data = parsed.envelope;

        let random_key = [0x42u8; SECRETBOX_KEY_LENGTH];
        let nonce: &[u8; NONCE_LENGTH] = envelope_data[..NONCE_LENGTH].try_into().unwrap();
        let ct_size = ENVELOPE_LENGTH - NONCE_LENGTH - SECRETBOX_MAC_LENGTH;
        let ciphertext = &envelope_data[NONCE_LENGTH..NONCE_LENGTH + ct_size];
        let tag: &[u8; SECRETBOX_MAC_LENGTH] =
            envelope_data[NONCE_LENGTH + ct_size..].try_into().unwrap();

        let mut plaintext = vec![0u8; ct_size];
        let result = crypto::decrypt_envelope(&random_key, ciphertext, nonce, tag, &mut plaintext);
        assert!(result.is_err(), "random key must not decrypt envelope");
    }

    #[test]
    fn correct_password_opens_envelope() {
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(PASSWORD, &responder);

        let (c_sk, _, s_sk, _) = authenticate(PASSWORD, &responder, &record);
        assert_eq!(c_sk, s_sk, "correct password must succeed");
    }

    #[test]
    fn wrong_password_dictionary_attack_fails() {
        let (responder, record) = setup();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

        let dictionary = [
            b"password123" as &[u8],
            b"letmein",
            b"admin",
            b"qwerty",
            b"123456",
        ];

        for wrong_pwd in &dictionary {
            let mut cs = InitiatorState::new();
            let mut ke1 = Ke1Message::new();
            generate_ke1(wrong_pwd, ACCOUNT_ID, &mut ke1, &mut cs).unwrap();

            let mut ke1_bytes = vec![0u8; KE1_LENGTH];
            protocol::write_ke1(
                &ke1.credential_request,
                &ke1.initiator_public_key,
                &ke1.initiator_nonce,
                &ke1.pq_ephemeral_public_key,
                &mut ke1_bytes,
            )
            .unwrap();

            let mut creds = ResponderCredentials::new();
            build_credentials(&record, &mut creds).unwrap();

            let mut ss = ResponderState::new();
            let mut ke2 = Ke2Message::new();
            generate_ke2(
                &responder, &ke1_bytes, ACCOUNT_ID, &creds, &mut ke2, &mut ss,
            )
            .unwrap();

            let mut ke2_bytes = vec![0u8; KE2_LENGTH];
            protocol::write_ke2(
                &ke2.responder_nonce,
                &ke2.responder_public_key,
                &ke2.credential_response,
                &ke2.responder_mac,
                &ke2.kem_ciphertext,
                &mut ke2_bytes,
            )
            .unwrap();

            let mut ke3 = Ke3Message::new();
            let result = generate_ke3(&initiator, &ke2_bytes, &mut cs, &mut ke3);
            assert!(
                result.is_err(),
                "dictionary password '{}' must not authenticate",
                std::str::from_utf8(wrong_pwd).unwrap_or("<binary>")
            );
        }
    }

    #[test]
    fn argon2id_computational_hardness() {
        let oprf_output = [0x42u8; HASH_LENGTH];
        let secure_key = b"test password for timing";

        let start = std::time::Instant::now();
        let mut out = [0u8; HASH_LENGTH];
        crypto::derive_randomized_password(&oprf_output, secure_key, &mut out).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() >= 100,
            "Argon2id must take >= 100ms, took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn different_passwords_different_envelopes() {
        let responder = OpaqueResponder::generate().unwrap();

        let record1 = register(b"password_alpha", &responder);
        let record2 = register(b"password_beta", &responder);
        assert_ne!(record1, record2);
    }

    #[test]
    fn record_uncorrelated_with_password() {
        let responder = OpaqueResponder::generate().unwrap();

        let passwords: &[&[u8]] = &[
            b"aaa", b"bbb", b"ccc", b"ddd", b"eee", b"fff", b"ggg", b"hhh", b"iii", b"jjj",
        ];

        let records: Vec<Vec<u8>> = passwords.iter().map(|p| register(p, &responder)).collect();

        for pos in VERSION_PREFIX_LENGTH..REGISTRATION_RECORD_LENGTH {
            let values: Vec<u8> = records.iter().map(|r| r[pos]).collect();
            let unique: std::collections::HashSet<u8> = values.iter().copied().collect();
            assert!(
                unique.len() >= 3,
                "byte position {} has too little variance: only {} unique values",
                pos,
                unique.len()
            );
        }
    }
}
