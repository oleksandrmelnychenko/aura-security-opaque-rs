// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_agent::*;
use opaque_core::protocol;
use opaque_core::types::*;
use opaque_relay::*;

const ACCOUNT_ID: &[u8] = b"alice@example.com";

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

    let mut server_session_key = [0u8; HASH_LENGTH];
    let mut server_master_key = [0u8; MASTER_KEY_LENGTH];
    responder_finish(
        &ke3_bytes,
        &mut server_state,
        &mut server_session_key,
        &mut server_master_key,
    )
    .unwrap();

    let mut client_session_key = [0u8; HASH_LENGTH];
    let mut client_master_key = [0u8; MASTER_KEY_LENGTH];
    initiator_finish(
        &mut client_state,
        &mut client_session_key,
        &mut client_master_key,
    )
    .unwrap();

    (
        client_session_key,
        client_master_key,
        server_session_key,
        server_master_key,
    )
}

#[test]
fn full_registration_and_authentication() {
    let password = b"correct horse battery staple";

    let responder = OpaqueResponder::generate().unwrap();

    let record_bytes = register(password, &responder);
    assert_eq!(record_bytes.len(), REGISTRATION_RECORD_LENGTH);

    let (c_sk, c_mk, s_sk, s_mk) = authenticate(password, &responder, &record_bytes);

    assert_eq!(c_sk, s_sk, "session keys must match");
    assert_eq!(c_mk, s_mk, "master keys must match");
    assert_eq!(c_sk.len(), HASH_LENGTH);
    assert_eq!(c_mk.len(), MASTER_KEY_LENGTH);

    assert!(!c_sk.iter().all(|&b| b == 0));
    assert!(!c_mk.iter().all(|&b| b == 0));
}

#[test]
fn wrong_password_fails_authentication() {
    let password = b"correct horse battery staple";
    let wrong_password = b"wrong password";

    let responder = OpaqueResponder::generate().unwrap();

    let record_bytes = register(password, &responder);

    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(wrong_password, ACCOUNT_ID, &mut ke1, &mut client_state).unwrap();

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
    let result = generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3);
    assert!(
        result.is_err(),
        "wrong password must cause authentication failure"
    );
}

#[test]
fn unknown_user_uses_fake_credentials_and_fails_client_side() {
    let password = b"correct horse battery staple";

    let responder = OpaqueResponder::generate().unwrap();
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

    let credentials = ResponderCredentials::new();
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
    let result = generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3);
    assert_eq!(result, Err(OpaqueError::AuthenticationError));
    assert_eq!(server_state.phase, ResponderPhase::Ke2Generated);
    assert!(!server_state
        .expected_initiator_mac()
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn multiple_registrations_produce_different_records() {
    let password = b"test password";

    let responder = OpaqueResponder::generate().unwrap();

    let record1 = register(password, &responder);
    let record2 = register(password, &responder);

    assert_ne!(
        record1, record2,
        "different registrations must produce different records"
    );
}

#[test]
fn different_sessions_produce_different_keys() {
    let password = b"test password";

    let responder = OpaqueResponder::generate().unwrap();

    let record = register(password, &responder);

    let (sk1, mk1, _, _) = authenticate(password, &responder, &record);
    let (sk2, mk2, _, _) = authenticate(password, &responder, &record);

    assert_ne!(
        sk1, sk2,
        "different sessions must produce different session keys"
    );
    assert_ne!(
        mk1, mk2,
        "different sessions must produce different master keys"
    );
}

#[test]
fn tampered_ke2_fails_authentication() {
    let password = b"test password";

    let responder = OpaqueResponder::generate().unwrap();
    let record = register(password, &responder);

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

    ke2_bytes[KE2_LENGTH - pq::KEM_CIPHERTEXT_LENGTH - 1] ^= 0xFF;

    let mut ke3 = Ke3Message::new();
    let result = generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3);
    assert!(
        result.is_err(),
        "tampered KE2 must cause authentication failure"
    );
    assert_eq!(client_state.phase, InitiatorPhase::Finished);

    let retry = generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3);
    assert!(
        matches!(retry, Err(OpaqueError::ValidationError)),
        "client state must be terminal after failed KE2 verification"
    );
}

#[test]
fn responder_finish_rejects_replay_after_failed_ke3() {
    let password = b"test password";
    let responder = OpaqueResponder::generate().unwrap();
    let record = register(password, &responder);
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

    let mut ke3_bytes = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes).unwrap();
    ke3_bytes[0] ^= 0xFF;

    let mut sk = [0u8; HASH_LENGTH];
    let mut mk = [0u8; MASTER_KEY_LENGTH];
    let first = responder_finish(&ke3_bytes, &mut server_state, &mut sk, &mut mk);
    assert!(first.is_err(), "tampered KE3 must fail");
    assert_eq!(server_state.phase, ResponderPhase::Finished);

    let zero_ke3 = [0u8; KE3_LENGTH];
    let second = responder_finish(&zero_ke3, &mut server_state, &mut sk, &mut mk);
    assert!(
        second.is_err(),
        "state must be terminal after failed KE3 verification"
    );
}

#[test]
fn responder_keypair_from_keys_roundtrip() {
    let kp = ResponderKeyPair::generate().unwrap();
    let kp2 = ResponderKeyPair::from_keys(&kp.private_key, &kp.public_key).unwrap();

    assert_eq!(kp.private_key, kp2.private_key);
    assert_eq!(kp.public_key, kp2.public_key);
}

#[test]
fn wire_format_sizes() {
    assert_eq!(KE1_LENGTH, 1273);
    assert_eq!(KE2_LENGTH, 1377);
    assert_eq!(KE3_LENGTH, 65);
    assert_eq!(REGISTRATION_REQUEST_LENGTH, 32);
    assert_eq!(REGISTRATION_RESPONSE_LENGTH, 64);
    assert_eq!(REGISTRATION_RECORD_LENGTH, 169);
}
