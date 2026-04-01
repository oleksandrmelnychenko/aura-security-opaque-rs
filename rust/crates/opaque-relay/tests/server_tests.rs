// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_core::crypto;
use opaque_core::protocol;
use opaque_core::types::*;
use opaque_relay::*;

#[test]
fn responder_keypair_generate_valid() {
    let kp = ResponderKeyPair::generate().unwrap();
    crypto::validate_public_key(&kp.public_key).unwrap();
    assert!(!kp.private_key.iter().all(|&b| b == 0));
}

#[test]
fn responder_keypair_from_keys_valid() {
    let kp = ResponderKeyPair::generate().unwrap();
    let kp2 = ResponderKeyPair::from_keys(&kp.private_key, &kp.public_key).unwrap();
    assert_eq!(kp.private_key, kp2.private_key);
    assert_eq!(kp.public_key, kp2.public_key);
}

#[test]
fn responder_keypair_from_keys_mismatched_fails() {
    let kp1 = ResponderKeyPair::generate().unwrap();
    let kp2 = ResponderKeyPair::generate().unwrap();
    assert!(ResponderKeyPair::from_keys(&kp1.private_key, &kp2.public_key).is_err());
}

#[test]
fn responder_keypair_from_keys_wrong_length_fails() {
    let short = [0u8; 16];
    let pk = [0u8; PUBLIC_KEY_LENGTH];
    assert!(ResponderKeyPair::from_keys(&short, &pk).is_err());
}

#[test]
fn opaque_responder_new_validates_key() {
    let kp = ResponderKeyPair::generate().unwrap();
    let seed = [42u8; OPRF_SEED_LENGTH];
    let responder = OpaqueResponder::new(kp.clone(), seed).unwrap();
    assert_eq!(responder.public_key(), &kp.public_key);
}

#[test]
fn opaque_responder_new_rejects_zero_seed() {
    let kp = ResponderKeyPair::generate().unwrap();
    let zero_seed = [0u8; OPRF_SEED_LENGTH];
    assert!(OpaqueResponder::new(kp, zero_seed).is_err());
}

#[test]
fn opaque_responder_generate_produces_valid_responder() {
    let responder = OpaqueResponder::generate().unwrap();
    crypto::validate_public_key(responder.public_key()).unwrap();

    // Ensure generated responder can perform OPRF evaluation through normal API.
    let mut resp = RegistrationResponse::new();
    let scalar = crypto::random_nonzero_scalar().unwrap();
    let point = crypto::scalarmult_base(&scalar).unwrap();
    let mut req_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
    protocol::write_registration_request(&point, &mut req_wire).unwrap();
    create_registration_response(&responder, &req_wire, b"alice", &mut resp).unwrap();
    assert_ne!(resp.data[..PUBLIC_KEY_LENGTH], [0u8; PUBLIC_KEY_LENGTH]);
}

#[test]
fn responder_state_new_zeroed() {
    let state = ResponderState::new();
    assert_eq!(*state.responder_private_key(), [0u8; PRIVATE_KEY_LENGTH]);
    assert_eq!(*state.session_key(), [0u8; HASH_LENGTH]);
    assert!(!state.handshake_complete);
}

#[test]
fn responder_credentials_new_default() {
    let creds = ResponderCredentials::new();
    assert_eq!(creds.envelope.len(), ENVELOPE_LENGTH);
    assert_eq!(creds.initiator_public_key, [0u8; PUBLIC_KEY_LENGTH]);
    assert!(!creds.registered);
}

#[test]
fn registration_response_correct_size() {
    let resp = RegistrationResponse::new();
    assert_eq!(resp.data.len(), REGISTRATION_RESPONSE_LENGTH);
}

#[test]
fn ke2_message_correct_sizes() {
    let ke2 = Ke2Message::new();
    assert_eq!(ke2.responder_nonce.len(), NONCE_LENGTH);
    assert_eq!(ke2.responder_public_key.len(), PUBLIC_KEY_LENGTH);
    assert_eq!(ke2.credential_response.len(), CREDENTIAL_RESPONSE_LENGTH);
    assert_eq!(ke2.responder_mac.len(), MAC_LENGTH);
    assert_eq!(ke2.kem_ciphertext.len(), pq::KEM_CIPHERTEXT_LENGTH);
}

#[test]
fn build_credentials_invalid_record_fails() {
    let mut creds = ResponderCredentials::new();
    let short = vec![0u8; 10];
    assert!(build_credentials(&short, &mut creds).is_err());
}

#[test]
fn build_credentials_already_registered_fails() {
    let mut creds = ResponderCredentials::new();
    creds.registered = true;
    let record = vec![0u8; REGISTRATION_RECORD_LENGTH];
    assert!(build_credentials(&record, &mut creds).is_err());
}

#[test]
fn create_registration_response_invalid_request_length_fails() {
    let responder = OpaqueResponder::generate().unwrap();
    let mut resp = RegistrationResponse::new();

    let bad_req = [0u8; 64];
    assert!(create_registration_response(&responder, &bad_req, b"alice", &mut resp).is_err());
}

#[test]
fn create_registration_response_empty_account_fails() {
    let responder = OpaqueResponder::generate().unwrap();
    let mut resp = RegistrationResponse::new();

    let scalar = crypto::random_nonzero_scalar().unwrap();
    let point = crypto::scalarmult_base(&scalar).unwrap();
    let mut req_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
    protocol::write_registration_request(&point, &mut req_wire).unwrap();

    assert!(create_registration_response(&responder, &req_wire, b"", &mut resp).is_err());
}
