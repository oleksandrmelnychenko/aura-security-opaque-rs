// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_core::types::{
    constant_time_eq, Envelope, OpaqueError, OpaqueResult, HASH_LENGTH, MAX_SECURE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, REGISTRATION_RESPONSE_WIRE_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, protocol};
use zeroize::Zeroize;

use crate::state::{
    InitiatorPhase, InitiatorState, OpaqueInitiator, RegistrationRecord, RegistrationRequest,
};

pub fn create_registration_request(
    secure_key: &[u8],
    request: &mut RegistrationRequest,
    state: &mut InitiatorState,
) -> OpaqueResult<()> {
    if secure_key.is_empty() || secure_key.len() > MAX_SECURE_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    if state.phase != InitiatorPhase::Created {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }

    state.initiator_private_key = crypto::random_nonzero_scalar()?;
    state.initiator_public_key = crypto::scalarmult_base(&state.initiator_private_key)?;

    state.secure_key.zeroize();
    state.secure_key[..secure_key.len()].copy_from_slice(secure_key);
    state.secure_key_len = secure_key.len();

    oprf::blind(
        secure_key,
        &mut request.data,
        &mut state.oblivious_prf_blind_scalar,
    )?;

    state.refresh_deadline();
    state.phase = InitiatorPhase::RegistrationRequested;
    Ok(())
}

pub fn finalize_registration(
    initiator: &OpaqueInitiator,
    registration_response: &[u8],
    state: &mut InitiatorState,
    record: &mut RegistrationRecord,
) -> OpaqueResult<()> {
    if registration_response.len() != REGISTRATION_RESPONSE_WIRE_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    if state.phase != InitiatorPhase::RegistrationRequested {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }

    let protocol::RegistrationResponseRef {
        evaluated_element,
        responder_public_key,
    } = protocol::parse_registration_response(registration_response)?;
    let expected_rpk = initiator.responder_public_key();

    crypto::validate_public_key(responder_public_key)?;
    if !constant_time_eq(responder_public_key, expected_rpk) {
        state.invalidate();
        return Err(OpaqueError::AuthenticationError);
    }

    let mut oprf_output = [0u8; HASH_LENGTH];
    oprf::finalize(
        &state.secure_key[..state.secure_key_len],
        &state.oblivious_prf_blind_scalar,
        evaluated_element
            .try_into()
            .map_err(|_| OpaqueError::InvalidProtocolMessage)?,
        &mut oprf_output,
    )?;

    let mut randomized_pwd = [0u8; HASH_LENGTH];
    crypto::derive_randomized_password(
        &oprf_output,
        &state.secure_key[..state.secure_key_len],
        &mut randomized_pwd,
    )?;
    state.secure_key.zeroize();
    state.secure_key_len = 0;
    state.oblivious_prf_blind_scalar.zeroize();

    let rpk: &[u8; PUBLIC_KEY_LENGTH] = responder_public_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;
    let mut env = Envelope::new();
    envelope::seal(
        &randomized_pwd,
        rpk,
        &state.initiator_private_key,
        &state.initiator_public_key,
        &mut env,
    )?;

    state.responder_public_key.copy_from_slice(rpk);

    record.envelope.clear();
    record.envelope.extend_from_slice(&env.nonce);
    record.envelope.extend_from_slice(&env.ciphertext);
    record.envelope.extend_from_slice(&env.auth_tag);
    record.initiator_public_key = state.initiator_public_key;

    oprf_output.zeroize();
    randomized_pwd.zeroize();
    state.secure_key.zeroize();
    state.secure_key_len = 0;
    state.oblivious_prf_blind_scalar.zeroize();

    state.phase = InitiatorPhase::RegistrationFinalized;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::types::{is_all_zero, REGISTRATION_RESPONSE_WIRE_LENGTH};
    use opaque_relay::OpaqueResponder;

    #[test]
    fn expired_registration_state_is_zeroized() {
        let responder = OpaqueResponder::generate().unwrap();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

        let mut state = InitiatorState::new();
        let mut request = RegistrationRequest::new();
        create_registration_request(b"correct horse battery staple", &mut request, &mut state)
            .unwrap();

        assert!(!is_all_zero(&state.secure_key[..state.secure_key_len]));
        assert!(!is_all_zero(&state.initiator_private_key));
        assert!(!is_all_zero(&state.oblivious_prf_blind_scalar));

        state.expire_for_test();

        let response = [0u8; REGISTRATION_RESPONSE_WIRE_LENGTH];
        let mut record = RegistrationRecord::new();
        let result = finalize_registration(&initiator, &response, &mut state, &mut record);
        assert_eq!(result, Err(OpaqueError::ValidationError));
        assert_eq!(state.phase, InitiatorPhase::Finished);
        assert!(is_all_zero(&state.secure_key));
        assert_eq!(state.secure_key_len, 0);
        assert!(is_all_zero(&state.initiator_private_key));
        assert!(is_all_zero(&state.oblivious_prf_blind_scalar));
    }
}
