use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3, InitiatorState,
    Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord, RegistrationRequest,
};
use opaque_core::types::{
    Envelope, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH, MASTER_KEY_LENGTH, NONCE_LENGTH,
    OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
    REGISTRATION_REQUEST_WIRE_LENGTH, REGISTRATION_RESPONSE_WIRE_LENGTH, SECRETBOX_MAC_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, protocol};
use opaque_relay::{
    build_credentials, create_registration_response, generate_ke2, responder_finish, Ke2Message,
    OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderState,
};

const ACCOUNT_ID: &[u8] = b"alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn register_record(responder: &OpaqueResponder) -> Vec<u8> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

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

    let mut out = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(&record.envelope, &record.initiator_public_key, &mut out)
        .unwrap();
    out
}

#[test]
fn regression_identity_point_injection_is_rejected() {
    let responder = OpaqueResponder::generate().unwrap();
    let identity = RistrettoPoint::identity().compress().to_bytes();
    let mut response = RegistrationResponse::new();

    let result = create_registration_response(&responder, &identity, ACCOUNT_ID, &mut response);
    assert!(result.is_err());
}

#[test]
#[ignore = "covered by integration.rs fast path"]
fn regression_ke3_retry_after_failed_verification_is_rejected() {
    let responder = OpaqueResponder::generate().unwrap();
    let record = register_record(&responder);
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

    let mut creds = ResponderCredentials::new();
    build_credentials(&record, &mut creds).unwrap();

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        &responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &creds,
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

    let mut tampered_ke3 = [0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut tampered_ke3).unwrap();
    tampered_ke3[0] ^= 0xFF;

    let mut session_key = [0u8; HASH_LENGTH];
    let mut master_key = [0u8; MASTER_KEY_LENGTH];
    assert!(responder_finish(
        &tampered_ke3,
        &mut server_state,
        &mut session_key,
        &mut master_key
    )
    .is_err());
    assert!(responder_finish(
        &[0u8; KE3_LENGTH],
        &mut server_state,
        &mut session_key,
        &mut master_key
    )
    .is_err());
}

#[test]
#[ignore = "slow compromise-boundary regression"]
fn regression_offline_dictionary_boundary_requires_protecting_oprf_seed() {
    let stolen_oprf_seed = [0x42u8; OPRF_SEED_LENGTH];
    let responder = OpaqueResponder::new(
        opaque_relay::ResponderKeyPair::generate().unwrap(),
        stolen_oprf_seed,
    )
    .unwrap();
    let registration_record = register_record(&responder);
    let stolen_server_pk = *responder.public_key();

    let dictionary: [&[u8]; 2] = [b"wrong-password", PASSWORD];

    let recovered = dictionary.iter().find(|guess| {
        let parsed = protocol::parse_registration_record(&registration_record).unwrap();

        let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind = [0u8; PRIVATE_KEY_LENGTH];
        oprf::blind(guess, &mut blinded, &mut blind).unwrap();

        let mut oprf_key = [0u8; PRIVATE_KEY_LENGTH];
        crypto::derive_oprf_key(&stolen_oprf_seed, ACCOUNT_ID, &mut oprf_key).unwrap();

        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();

        let mut oprf_output = [0u8; HASH_LENGTH];
        oprf::finalize(guess, &blind, &evaluated, &mut oprf_output).unwrap();

        let mut randomized_pwd = [0u8; HASH_LENGTH];
        crypto::derive_randomized_password(&oprf_output, guess, &mut randomized_pwd).unwrap();

        let ct_size = parsed.envelope.len() - NONCE_LENGTH - SECRETBOX_MAC_LENGTH;
        let env = Envelope {
            nonce: parsed.envelope[..NONCE_LENGTH].to_vec(),
            ciphertext: parsed.envelope[NONCE_LENGTH..NONCE_LENGTH + ct_size].to_vec(),
            auth_tag: parsed.envelope[NONCE_LENGTH + ct_size..].to_vec(),
        };

        let mut recovered_rpk = [0u8; PUBLIC_KEY_LENGTH];
        let mut recovered_isk = [0u8; PRIVATE_KEY_LENGTH];
        let mut recovered_ipk = [0u8; PUBLIC_KEY_LENGTH];

        envelope::open(
            &env,
            &randomized_pwd,
            &stolen_server_pk,
            &mut recovered_rpk,
            &mut recovered_isk,
            &mut recovered_ipk,
        )
        .is_ok()
            && recovered_rpk == stolen_server_pk
            && recovered_ipk == parsed.initiator_public_key
    });

    assert_eq!(recovered.copied(), Some(PASSWORD));
}
