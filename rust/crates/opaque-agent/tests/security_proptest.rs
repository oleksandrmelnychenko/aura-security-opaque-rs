// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_agent::*;
use opaque_core::protocol;
use opaque_core::types::*;
use opaque_relay::*;
use proptest::prelude::*;

type AuthResult = Result<
    (
        [u8; HASH_LENGTH],
        [u8; MASTER_KEY_LENGTH],
        [u8; HASH_LENGTH],
        [u8; MASTER_KEY_LENGTH],
    ),
    Box<dyn std::error::Error>,
>;

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

fn authenticate(password: &[u8], responder: &OpaqueResponder, record_bytes: &[u8]) -> AuthResult {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(password, ACCOUNT_ID, &mut ke1, &mut client_state)?;

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )?;

    let mut credentials = ResponderCredentials::new();
    build_credentials(record_bytes, &mut credentials)?;

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &credentials,
        &mut ke2,
        &mut server_state,
    )?;

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )?;

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3)?;

    let mut ke3_bytes = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes)?;

    let mut server_session_key = [0u8; HASH_LENGTH];
    let mut server_master_key = [0u8; MASTER_KEY_LENGTH];
    responder_finish(
        &ke3_bytes,
        &mut server_state,
        &mut server_session_key,
        &mut server_master_key,
    )?;

    let mut client_session_key = [0u8; HASH_LENGTH];
    let mut client_master_key = [0u8; MASTER_KEY_LENGTH];
    initiator_finish(
        &mut client_state,
        &mut client_session_key,
        &mut client_master_key,
    )?;

    Ok((
        client_session_key,
        client_master_key,
        server_session_key,
        server_master_key,
    ))
}

fn try_generate_ke3(
    password: &[u8],
    responder: &OpaqueResponder,
    record_bytes: &[u8],
    tamper_ke2: impl FnOnce(&mut Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(password, ACCOUNT_ID, &mut ke1, &mut client_state)?;

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )?;

    let mut credentials = ResponderCredentials::new();
    build_credentials(record_bytes, &mut credentials)?;

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &credentials,
        &mut ke2,
        &mut server_state,
    )?;

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )?;

    tamper_ke2(&mut ke2_bytes);

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3)?;
    Ok(())
}

fn try_responder_finish(
    password: &[u8],
    responder: &OpaqueResponder,
    record_bytes: &[u8],
    tamper_ke3: impl FnOnce(&mut Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(password, ACCOUNT_ID, &mut ke1, &mut client_state)?;

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )?;

    let mut credentials = ResponderCredentials::new();
    build_credentials(record_bytes, &mut credentials)?;

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &credentials,
        &mut ke2,
        &mut server_state,
    )?;

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )?;

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3)?;

    let mut ke3_bytes = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut ke3_bytes)?;

    tamper_ke3(&mut ke3_bytes);

    let mut server_session_key = [0u8; HASH_LENGTH];
    let mut server_master_key = [0u8; MASTER_KEY_LENGTH];
    responder_finish(
        &ke3_bytes,
        &mut server_state,
        &mut server_session_key,
        &mut server_master_key,
    )?;
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn prop_session_keys_always_match(password in prop::collection::vec(1u8..=255, 1..=128)) {
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(&password, &responder);
        let (c_sk, c_mk, s_sk, s_mk) = authenticate(&password, &responder, &record).unwrap();
        prop_assert_eq!(&c_sk, &s_sk, "session keys must match");
        prop_assert_eq!(&c_mk, &s_mk, "master keys must match");
        prop_assert!(c_sk.len() == HASH_LENGTH);
        prop_assert!(!c_sk.iter().all(|&b| b == 0));
    }

    #[test]
    fn prop_wrong_password_always_fails(
        password in prop::collection::vec(1u8..=255, 1..=64),
        wrong_password in prop::collection::vec(1u8..=255, 1..=64),
    ) {
        prop_assume!(password != wrong_password);
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(&password, &responder);
        let result = authenticate(&wrong_password, &responder, &record);
        prop_assert!(result.is_err(), "wrong password must fail authentication");
    }

    #[test]
    fn prop_different_sessions_different_keys(password in prop::collection::vec(1u8..=255, 1..=64)) {
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(&password, &responder);
        let (sk1, _, _, _) = authenticate(&password, &responder, &record).unwrap();
        let (sk2, _, _, _) = authenticate(&password, &responder, &record).unwrap();
        prop_assert_ne!(sk1, sk2, "different sessions must produce different session keys");
    }

    #[test]
    fn prop_tampered_ke2_always_detected(
        tamper_offset in 0usize..KE2_LENGTH,
        tamper_xor in 1u8..=255u8,
    ) {
        let password = b"proptest password";
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(password, &responder);

        let result = try_generate_ke3(password, &responder, &record, |ke2_bytes| {
            ke2_bytes[tamper_offset] ^= tamper_xor;
        });
        prop_assert!(result.is_err(), "tampered KE2 at offset {} must be detected", tamper_offset);
    }

    #[test]
    fn prop_tampered_ke3_always_detected(
        tamper_offset in 0usize..KE3_LENGTH,
        tamper_xor in 1u8..=255u8,
    ) {
        let password = b"proptest password";
        let responder = OpaqueResponder::generate().unwrap();
        let record = register(password, &responder);

        let result = try_responder_finish(password, &responder, &record, |ke3_bytes| {
            ke3_bytes[tamper_offset] ^= tamper_xor;
        });
        prop_assert!(result.is_err(), "tampered KE3 at offset {} must be detected", tamper_offset);
    }
}
