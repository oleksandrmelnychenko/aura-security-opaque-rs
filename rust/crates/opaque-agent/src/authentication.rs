// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_core::types::{
    constant_time_eq, labels, pq, pq_labels, OpaqueError, OpaqueResult, CLASSICAL_IKM_LENGTH,
    CREDENTIAL_RESPONSE_LENGTH, DH_COMPONENT_COUNT, ENVELOPE_LENGTH, HASH_LENGTH, KE2_LENGTH,
    MAC_LENGTH, MASTER_KEY_LENGTH, MAX_SECURE_KEY_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, SECRETBOX_MAC_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, pq_kem, protocol};
use zeroize::{Zeroize, Zeroizing};

use crate::state::{InitiatorPhase, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator};

const TRANSCRIPT_INPUT_LENGTH: usize = 2 * NONCE_LENGTH
    + DH_COMPONENT_COUNT * PUBLIC_KEY_LENGTH
    + CREDENTIAL_RESPONSE_LENGTH
    + pq::KEM_CIPHERTEXT_LENGTH
    + pq::KEM_PUBLIC_KEY_LENGTH
    + HASH_LENGTH;

pub fn generate_ke1(
    secure_key: &[u8],
    account_id: &[u8],
    ke1: &mut Ke1Message,
    state: &mut InitiatorState,
) -> OpaqueResult<()> {
    if secure_key.is_empty() || secure_key.len() > MAX_SECURE_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    if account_id.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if state.phase != InitiatorPhase::Created {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }
    state.secure_key.zeroize();
    state.secure_key[..secure_key.len()].copy_from_slice(secure_key);
    state.secure_key_len = secure_key.len();
    state.account_context_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::ACCOUNT_CONTEXT_BINDING, account_id],
        &mut state.account_context_hash,
    );

    state.initiator_ephemeral_private_key = crypto::random_nonzero_scalar()?;
    state.initiator_ephemeral_public_key =
        crypto::scalarmult_base(&state.initiator_ephemeral_private_key)?;

    state.pq_ephemeral_public_key = [0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    state.pq_ephemeral_secret_key = [0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(
        &mut state.pq_ephemeral_public_key,
        &mut state.pq_ephemeral_secret_key,
    )?;

    crypto::random_bytes(&mut ke1.initiator_nonce)?;
    state.initiator_nonce = ke1.initiator_nonce;

    ke1.initiator_public_key = state.initiator_ephemeral_public_key;

    oprf::blind(
        secure_key,
        &mut ke1.credential_request,
        &mut state.oblivious_prf_blind_scalar,
    )?;

    ke1.pq_ephemeral_public_key = state.pq_ephemeral_public_key;

    state.phase = InitiatorPhase::Ke1Generated;
    Ok(())
}

pub fn generate_ke3(
    initiator: &OpaqueInitiator,
    ke2_data: &[u8],
    state: &mut InitiatorState,
    ke3: &mut Ke3Message,
) -> OpaqueResult<()> {
    if ke2_data.len() != KE2_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    if state.phase != InitiatorPhase::Ke1Generated {
        return Err(OpaqueError::ValidationError);
    }
    if state.is_expired() {
        state.invalidate();
        return Err(OpaqueError::ValidationError);
    }
    if opaque_core::types::is_all_zero(&state.account_context_hash) {
        return Err(OpaqueError::ValidationError);
    }

    let result = (|| -> OpaqueResult<()> {
        let responder_public_key = initiator.responder_public_key();
        crypto::validate_public_key(responder_public_key)?;

        let protocol::Ke2Ref {
            responder_nonce,
            responder_public_key: responder_ephemeral_public_key,
            credential_response,
            responder_mac,
            kem_ciphertext,
        } = protocol::parse_ke2(ke2_data)?;

        crypto::validate_public_key(responder_ephemeral_public_key)?;

        let evaluated_elem = &credential_response[..PUBLIC_KEY_LENGTH];
        let envelope_data = &credential_response[PUBLIC_KEY_LENGTH..];

        let mut oprf_output = Zeroizing::new([0u8; HASH_LENGTH]);
        oprf::finalize(
            &state.secure_key[..state.secure_key_len],
            &state.oblivious_prf_blind_scalar,
            evaluated_elem
                .try_into()
                .map_err(|_| OpaqueError::InvalidProtocolMessage)?,
            &mut oprf_output,
        )?;

        let mut randomized_pwd = Zeroizing::new([0u8; HASH_LENGTH]);
        crypto::derive_randomized_password(
            &*oprf_output,
            &state.secure_key[..state.secure_key_len],
            &mut *randomized_pwd,
        )?;
        state.secure_key.zeroize();
        state.secure_key_len = 0;
        state.oblivious_prf_blind_scalar.zeroize();

        let ct_size = ENVELOPE_LENGTH - NONCE_LENGTH - SECRETBOX_MAC_LENGTH;
        let env_nonce = &envelope_data[..NONCE_LENGTH];
        let env_ciphertext = &envelope_data[NONCE_LENGTH..NONCE_LENGTH + ct_size];
        let env_auth_tag = &envelope_data[NONCE_LENGTH + ct_size..];

        let mut recovered_rpk = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);
        let mut recovered_isk = Zeroizing::new([0u8; PRIVATE_KEY_LENGTH]);
        let mut recovered_ipk = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);

        envelope::open_raw(
            env_nonce,
            env_ciphertext,
            env_auth_tag,
            &*randomized_pwd,
            responder_public_key,
            &mut recovered_rpk,
            &mut recovered_isk,
            &mut recovered_ipk,
        )?;

        if !constant_time_eq(&*recovered_rpk, responder_public_key) {
            return Err(OpaqueError::AuthenticationError);
        }

        let resp_eph_pk: &[u8; PUBLIC_KEY_LENGTH] = responder_ephemeral_public_key
            .try_into()
            .map_err(|_| OpaqueError::InvalidProtocolMessage)?;

        let mut dh1 = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);
        let mut dh2 = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);
        let mut dh3 = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);

        let mut dh4 = Zeroizing::new([0u8; PUBLIC_KEY_LENGTH]);

        crypto::scalar_mult(&recovered_isk, &recovered_rpk, &mut dh1)?;
        crypto::scalar_mult(
            &state.initiator_ephemeral_private_key,
            &recovered_rpk,
            &mut dh2,
        )?;
        crypto::scalar_mult(&recovered_isk, resp_eph_pk, &mut dh3)?;
        crypto::scalar_mult(
            &state.initiator_ephemeral_private_key,
            resp_eph_pk,
            &mut dh4,
        )?;

        let mut kem_ss = Zeroizing::new([0u8; pq::KEM_SHARED_SECRET_LENGTH]);
        pq_kem::decapsulate(&state.pq_ephemeral_secret_key, kem_ciphertext, &mut *kem_ss)?;

        state.pq_ephemeral_secret_key.zeroize();
        state.pq_shared_secret = *kem_ss;

        let mut classical_ikm = Zeroizing::new([0u8; CLASSICAL_IKM_LENGTH]);
        classical_ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&*dh1);
        classical_ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&*dh2);
        classical_ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&*dh3);
        classical_ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&*dh4);

        let mut mac_input = Zeroizing::new([0u8; TRANSCRIPT_INPUT_LENGTH]);
        let mut off = 0;

        let mut append = |data: &[u8]| {
            mac_input[off..off + data.len()].copy_from_slice(data);
            off += data.len();
        };
        append(&state.initiator_ephemeral_public_key);
        append(resp_eph_pk);
        append(&state.initiator_nonce);
        append(responder_nonce);
        append(&*recovered_ipk);
        append(&*recovered_rpk);
        append(credential_response);
        append(&state.pq_ephemeral_public_key);
        append(kem_ciphertext);
        append(&state.account_context_hash);

        let mut transcript_hash = Zeroizing::new([0u8; HASH_LENGTH]);
        crypto::sha512_multi(
            &[labels::TRANSCRIPT_CONTEXT, &mac_input[..off]],
            &mut transcript_hash,
        );

        let mut prk = Zeroizing::new([0u8; HASH_LENGTH]);
        pq_kem::combine_key_material(&*classical_ikm, &*kem_ss, &*transcript_hash, &mut prk)?;

        let mut session_key = Zeroizing::new([0u8; HASH_LENGTH]);
        crypto::key_derivation_expand(&*prk, pq_labels::PQ_SESSION_KEY_INFO, &mut *session_key)?;

        let mut master_key = Zeroizing::new([0u8; MASTER_KEY_LENGTH]);
        crypto::key_derivation_expand(&*prk, pq_labels::PQ_MASTER_KEY_INFO, &mut *master_key)?;

        let mut resp_mac_key = Zeroizing::new([0u8; MAC_LENGTH]);
        crypto::key_derivation_expand(&*prk, pq_labels::PQ_RESPONDER_MAC_INFO, &mut *resp_mac_key)?;

        let mut expected_resp_mac = Zeroizing::new([0u8; MAC_LENGTH]);
        crypto::hmac_sha512(&*resp_mac_key, &mac_input[..off], &mut expected_resp_mac)?;

        if !constant_time_eq(responder_mac, &*expected_resp_mac) {
            return Err(OpaqueError::AuthenticationError);
        }

        let mut init_mac_key = Zeroizing::new([0u8; MAC_LENGTH]);
        crypto::key_derivation_expand(&*prk, pq_labels::PQ_INITIATOR_MAC_INFO, &mut *init_mac_key)?;
        crypto::hmac_sha512(&*init_mac_key, &mac_input[..off], &mut ke3.initiator_mac)?;

        state.responder_public_key = *recovered_rpk;
        state.initiator_private_key = *recovered_isk;
        state.initiator_public_key = *recovered_ipk;
        state.master_key = *master_key;
        state.session_key = *session_key;

        state.phase = InitiatorPhase::Ke3Generated;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            state.invalidate();
            Err(err)
        }
    }
}

pub fn initiator_finish(
    state: &mut InitiatorState,
    session_key: &mut [u8; HASH_LENGTH],
    master_key: &mut [u8; MASTER_KEY_LENGTH],
) -> OpaqueResult<()> {
    if state.phase != InitiatorPhase::Ke3Generated {
        return Err(OpaqueError::ValidationError);
    }
    if opaque_core::types::is_all_zero(&state.session_key) {
        return Err(OpaqueError::InvalidInput);
    }

    session_key.copy_from_slice(&state.session_key);
    master_key.copy_from_slice(&state.master_key);
    state.session_key.zeroize();
    state.master_key.zeroize();

    state.pq_shared_secret.zeroize();
    state.pq_ephemeral_secret_key.zeroize();
    state.secure_key.zeroize();
    state.secure_key_len = 0;
    state.account_context_hash.zeroize();
    state.oblivious_prf_blind_scalar.zeroize();
    state.initiator_private_key.zeroize();
    state.initiator_ephemeral_private_key.zeroize();

    state.phase = InitiatorPhase::Finished;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_core::types::{is_all_zero, KE2_LENGTH};
    use opaque_relay::OpaqueResponder;

    #[test]
    fn expired_authentication_state_is_zeroized() {
        let responder = OpaqueResponder::generate().unwrap();
        let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

        let mut state = InitiatorState::new();
        let mut ke1 = Ke1Message::new();
        generate_ke1(
            b"correct horse battery staple",
            b"alice@example.com",
            &mut ke1,
            &mut state,
        )
        .unwrap();

        assert!(!is_all_zero(&state.secure_key[..state.secure_key_len]));
        assert!(!is_all_zero(&state.initiator_ephemeral_private_key));
        assert!(!is_all_zero(&state.pq_ephemeral_secret_key));
        assert!(!is_all_zero(&state.oblivious_prf_blind_scalar));
        assert!(!is_all_zero(&state.account_context_hash));

        state.expire_for_test();

        let mut ke3 = Ke3Message::new();
        let ke2 = [0u8; KE2_LENGTH];
        let result = generate_ke3(&initiator, &ke2, &mut state, &mut ke3);
        assert_eq!(result, Err(OpaqueError::ValidationError));
        assert_eq!(state.phase, InitiatorPhase::Finished);
        assert!(is_all_zero(&state.secure_key));
        assert_eq!(state.secure_key_len, 0);
        assert!(is_all_zero(&state.initiator_ephemeral_private_key));
        assert!(is_all_zero(&state.pq_ephemeral_secret_key));
        assert!(is_all_zero(&state.oblivious_prf_blind_scalar));
        assert!(is_all_zero(&state.account_context_hash));
    }
}
