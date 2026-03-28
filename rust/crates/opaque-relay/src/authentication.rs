// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_core::types::{
    constant_time_eq, ct_select_bytes, labels, pq, pq_labels, OpaqueError, OpaqueResult,
    CLASSICAL_IKM_LENGTH, CREDENTIAL_RESPONSE_LENGTH, DH_COMPONENT_COUNT, ENVELOPE_LENGTH,
    HASH_LENGTH, KE1_LENGTH, KE3_LENGTH, MAC_LENGTH, MASTER_KEY_LENGTH, NONCE_LENGTH,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
};
use opaque_core::{crypto, pq_kem, protocol};
use subtle::Choice;
use zeroize::Zeroize;

use crate::state::{
    Ke2Message, OpaqueResponder, ResponderCredentials, ResponderPhase, ResponderState,
};

const TRANSCRIPT_INPUT_LENGTH: usize = 2 * NONCE_LENGTH
    + DH_COMPONENT_COUNT * PUBLIC_KEY_LENGTH
    + CREDENTIAL_RESPONSE_LENGTH
    + pq::KEM_CIPHERTEXT_LENGTH
    + pq::KEM_PUBLIC_KEY_LENGTH
    + HASH_LENGTH;

fn select_credentials(
    responder: &OpaqueResponder,
    account_id: &[u8],
    credentials: &ResponderCredentials,
) -> OpaqueResult<([u8; PUBLIC_KEY_LENGTH], [u8; ENVELOPE_LENGTH])> {
    let mut fake_material = responder.evaluator().derive_fake_material(account_id)?;
    let mut fake_private_key = [0u8; PRIVATE_KEY_LENGTH];
    let mut fake_public_key = [0u8; PUBLIC_KEY_LENGTH];
    crypto::derive_key_pair(&fake_material, &mut fake_private_key, &mut fake_public_key)?;

    let mut fake_envelope = [0u8; ENVELOPE_LENGTH];
    crypto::key_derivation_expand(
        &fake_material,
        labels::FAKE_CREDENTIALS_CONTEXT,
        &mut fake_envelope,
    )?;
    fake_material.zeroize();
    fake_private_key.zeroize();

    let mut real_public_key = [0u8; PUBLIC_KEY_LENGTH];
    let mut real_envelope = [0u8; ENVELOPE_LENGTH];
    if credentials.registered {
        if credentials.envelope.len() != ENVELOPE_LENGTH {
            fake_public_key.zeroize();
            fake_envelope.zeroize();
            return Err(OpaqueError::ValidationError);
        }

        crypto::validate_public_key(&credentials.initiator_public_key)?;
        let envelope: &[u8; ENVELOPE_LENGTH] = credentials
            .envelope
            .as_slice()
            .try_into()
            .map_err(|_| OpaqueError::ValidationError)?;
        real_public_key.copy_from_slice(&credentials.initiator_public_key);
        real_envelope.copy_from_slice(envelope);
    }

    let choice = Choice::from(u8::from(credentials.registered));
    let mut selected_public_key = [0u8; PUBLIC_KEY_LENGTH];
    let mut selected_envelope = [0u8; ENVELOPE_LENGTH];
    ct_select_bytes(
        &mut selected_public_key,
        &real_public_key,
        &fake_public_key,
        choice,
    );
    ct_select_bytes(
        &mut selected_envelope,
        &real_envelope,
        &fake_envelope,
        choice,
    );

    fake_public_key.zeroize();
    fake_envelope.zeroize();
    real_public_key.zeroize();
    real_envelope.zeroize();

    Ok((selected_public_key, selected_envelope))
}

pub fn generate_ke2(
    responder: &OpaqueResponder,
    ke1_data: &[u8],
    account_id: &[u8],
    credentials: &ResponderCredentials,
    ke2: &mut Ke2Message,
    state: &mut ResponderState,
) -> OpaqueResult<()> {
    if ke1_data.len() != KE1_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    if state.phase != ResponderPhase::Created {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }
    if account_id.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let ke1 = protocol::parse_ke1(ke1_data)?;
    let kp = responder.keypair();

    let init_eph_pk: &[u8; PUBLIC_KEY_LENGTH] = ke1
        .initiator_public_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;
    let (selected_pk, selected_envelope) = select_credentials(responder, account_id, credentials)?;
    let mut account_context_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::ACCOUNT_CONTEXT_BINDING, account_id],
        &mut account_context_hash,
    );

    crypto::validate_ristretto_point(ke1.credential_request)?;
    crypto::validate_public_key(init_eph_pk)?;
    crypto::validate_public_key(&selected_pk)?;

    state.initiator_public_key = *init_eph_pk;
    state.responder_private_key = kp.private_key;
    state.responder_public_key = kp.public_key;
    state.handshake_complete = false;

    state.responder_ephemeral_private_key = crypto::random_nonzero_scalar()?;
    state.responder_ephemeral_public_key =
        crypto::scalarmult_base(&state.responder_ephemeral_private_key)?;

    crypto::random_bytes(&mut ke2.responder_nonce)?;
    ke2.responder_public_key = state.responder_ephemeral_public_key;

    let cred_req: &[u8; PUBLIC_KEY_LENGTH] = ke1
        .credential_request
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;
    let evaluated_elem = responder.evaluator().evaluate_oprf(cred_req, account_id)?;

    ke2.credential_response[..PUBLIC_KEY_LENGTH].copy_from_slice(&evaluated_elem);
    ke2.credential_response[PUBLIC_KEY_LENGTH..].copy_from_slice(&selected_envelope);

    let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];

    let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];

    crypto::scalar_mult(&kp.private_key, &selected_pk, &mut dh1)?;
    crypto::scalar_mult(&kp.private_key, init_eph_pk, &mut dh2)?;
    crypto::scalar_mult(
        &state.responder_ephemeral_private_key,
        &selected_pk,
        &mut dh3,
    )?;
    crypto::scalar_mult(
        &state.responder_ephemeral_private_key,
        init_eph_pk,
        &mut dh4,
    )?;

    let mut kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(
        ke1.pq_ephemeral_public_key,
        &mut ke2.kem_ciphertext,
        &mut kem_ss,
    )?;
    state.pq_shared_secret = kem_ss;

    let mut classical_ikm = [0u8; CLASSICAL_IKM_LENGTH];
    classical_ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
    classical_ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
    classical_ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
    classical_ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);

    let mut mac_input = [0u8; TRANSCRIPT_INPUT_LENGTH];
    let mut off = 0;

    let mut append = |data: &[u8]| {
        mac_input[off..off + data.len()].copy_from_slice(data);
        off += data.len();
    };
    append(init_eph_pk);
    append(&state.responder_ephemeral_public_key);
    append(ke1.initiator_nonce);
    append(&ke2.responder_nonce);
    append(&selected_pk);
    append(&kp.public_key);
    append(&ke2.credential_response);
    append(ke1.pq_ephemeral_public_key);
    append(&ke2.kem_ciphertext);
    append(&account_context_hash);

    let mut transcript_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::TRANSCRIPT_CONTEXT, &mac_input[..off]],
        &mut transcript_hash,
    );

    let mut prk = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, &kem_ss, &transcript_hash, &mut prk)?;

    state.session_key = [0u8; HASH_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut state.session_key)?;

    state.master_key = [0u8; MASTER_KEY_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_MASTER_KEY_INFO, &mut state.master_key)?;

    let mut resp_mac_key = [0u8; MAC_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_RESPONDER_MAC_INFO, &mut resp_mac_key)?;
    crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut ke2.responder_mac)?;

    let mut init_mac_key = [0u8; MAC_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_INITIATOR_MAC_INFO, &mut init_mac_key)?;
    crypto::hmac_sha512(&init_mac_key, &mac_input, &mut state.expected_initiator_mac)?;

    classical_ikm.zeroize();
    mac_input.zeroize();
    prk.zeroize();
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    dh4.zeroize();
    kem_ss.zeroize();
    resp_mac_key.zeroize();
    init_mac_key.zeroize();
    transcript_hash.zeroize();
    account_context_hash.zeroize();
    state.phase = ResponderPhase::Ke2Generated;
    Ok(())
}

pub fn responder_finish(
    ke3_data: &[u8],
    state: &mut ResponderState,
    session_key: &mut [u8; HASH_LENGTH],
    master_key: &mut [u8; MASTER_KEY_LENGTH],
) -> OpaqueResult<()> {
    if ke3_data.len() != KE3_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    if state.phase != ResponderPhase::Ke2Generated {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }
    if opaque_core::types::is_all_zero(&state.session_key) {
        return Err(OpaqueError::ValidationError);
    }

    let ke3 = match protocol::parse_ke3(ke3_data) {
        Ok(ke3) => ke3,
        Err(e) => {
            state.session_key.zeroize();
            state.master_key.zeroize();
            state.pq_shared_secret.zeroize();
            state.expected_initiator_mac.zeroize();
            state.responder_ephemeral_private_key.zeroize();
            state.responder_private_key.zeroize();
            state.handshake_complete = false;
            state.phase = ResponderPhase::Finished;
            return Err(e);
        }
    };

    if !constant_time_eq(ke3.initiator_mac, &state.expected_initiator_mac) {
        state.session_key.zeroize();
        state.master_key.zeroize();
        state.pq_shared_secret.zeroize();
        state.expected_initiator_mac.zeroize();
        state.responder_ephemeral_private_key.zeroize();
        state.responder_private_key.zeroize();
        state.handshake_complete = false;
        state.phase = ResponderPhase::Finished;
        return Err(OpaqueError::AuthenticationError);
    }

    session_key.copy_from_slice(&state.session_key);
    master_key.copy_from_slice(&state.master_key);
    state.session_key.zeroize();
    state.master_key.zeroize();

    state.pq_shared_secret.zeroize();
    state.expected_initiator_mac.zeroize();
    state.responder_ephemeral_private_key.zeroize();
    state.responder_private_key.zeroize();
    state.handshake_complete = true;
    state.phase = ResponderPhase::Finished;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_agent::{
        create_registration_request, finalize_registration, generate_ke1, Ke1Message,
        OpaqueInitiator, RegistrationRecord, RegistrationRequest,
    };
    use opaque_core::types::{
        is_all_zero, KE3_LENGTH, REGISTRATION_RECORD_LENGTH, REGISTRATION_REQUEST_WIRE_LENGTH,
        REGISTRATION_RESPONSE_WIRE_LENGTH,
    };

    #[test]
    fn expired_responder_state_is_zeroized() {
        let account_id = b"alice@example.com";
        let password = b"correct horse battery staple";
        let responder = OpaqueResponder::generate().unwrap();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

        let mut registration_state = opaque_agent::InitiatorState::new();
        let mut registration_request = RegistrationRequest::new();
        create_registration_request(password, &mut registration_request, &mut registration_state)
            .unwrap();

        let mut registration_request_wire = vec![0u8; REGISTRATION_REQUEST_WIRE_LENGTH];
        protocol::write_registration_request(
            &registration_request.data,
            &mut registration_request_wire,
        )
        .unwrap();

        let mut registration_response = crate::RegistrationResponse::new();
        crate::create_registration_response(
            &responder,
            &registration_request_wire,
            account_id,
            &mut registration_response,
        )
        .unwrap();

        let mut registration_response_wire = vec![0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
        protocol::write_registration_response(
            &registration_response.data[..PUBLIC_KEY_LENGTH],
            &registration_response.data[PUBLIC_KEY_LENGTH..],
            &mut registration_response_wire,
        )
        .unwrap();

        let mut record = RegistrationRecord::new();
        finalize_registration(
            &initiator,
            &registration_response_wire,
            &mut registration_state,
            &mut record,
        )
        .unwrap();

        let mut record_bytes = vec![0u8; REGISTRATION_RECORD_LENGTH];
        protocol::write_registration_record(
            &record.envelope,
            &record.initiator_public_key,
            &mut record_bytes,
        )
        .unwrap();

        let mut credentials = ResponderCredentials::new();
        crate::build_credentials(&record_bytes, &mut credentials).unwrap();

        let mut client_state = opaque_agent::InitiatorState::new();
        let mut ke1 = Ke1Message::new();
        generate_ke1(password, account_id, &mut ke1, &mut client_state).unwrap();

        let mut ke1_bytes = vec![0u8; KE1_LENGTH];
        protocol::write_ke1(
            &ke1.credential_request,
            &ke1.initiator_public_key,
            &ke1.initiator_nonce,
            &ke1.pq_ephemeral_public_key,
            &mut ke1_bytes,
        )
        .unwrap();

        let mut state = ResponderState::new();
        let mut ke2 = Ke2Message::new();
        generate_ke2(
            &responder,
            &ke1_bytes,
            account_id,
            &credentials,
            &mut ke2,
            &mut state,
        )
        .unwrap();

        assert!(!is_all_zero(&state.responder_private_key));
        assert!(!is_all_zero(&state.responder_ephemeral_private_key));
        assert!(!is_all_zero(&state.expected_initiator_mac));
        assert!(!is_all_zero(&state.pq_shared_secret));

        state.expire_for_test();

        let ke3 = [0u8; KE3_LENGTH];
        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; MASTER_KEY_LENGTH];
        let result = responder_finish(&ke3, &mut state, &mut session_key, &mut master_key);
        assert_eq!(result, Err(OpaqueError::ValidationError));
        assert_eq!(state.phase, ResponderPhase::Finished);
        assert!(!state.handshake_complete);
        assert!(is_all_zero(&state.responder_private_key));
        assert!(is_all_zero(&state.responder_ephemeral_private_key));
        assert!(is_all_zero(&state.expected_initiator_mac));
        assert!(is_all_zero(&state.pq_shared_secret));
        assert!(is_all_zero(&state.session_key));
        assert!(is_all_zero(&state.master_key));
    }
}
