// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use opaque_core::types::{OpaqueError, OpaqueResult, PUBLIC_KEY_LENGTH};
use opaque_core::{crypto, protocol};

use crate::state::{OpaqueResponder, RegistrationResponse, ResponderCredentials};

pub fn create_registration_response(
    responder: &OpaqueResponder,
    registration_request: &[u8],
    account_id: &[u8],
    response: &mut RegistrationResponse,
) -> OpaqueResult<()> {
    let payload = protocol::parse_registration_request(registration_request)?;
    if account_id.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    crypto::validate_ristretto_point(payload)?;

    let blinded: &[u8; PUBLIC_KEY_LENGTH] = payload
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;
    let evaluated = responder.evaluator().evaluate_oprf(blinded, account_id)?;

    response.data[..PUBLIC_KEY_LENGTH].copy_from_slice(&evaluated);
    response.data[PUBLIC_KEY_LENGTH..].copy_from_slice(responder.public_key());

    Ok(())
}

pub fn build_credentials(
    registration_record: &[u8],
    credentials: &mut ResponderCredentials,
) -> OpaqueResult<()> {
    if credentials.registered {
        return Err(OpaqueError::AlreadyRegistered);
    }

    let view = protocol::parse_registration_record(registration_record)?;

    crypto::validate_public_key(view.initiator_public_key)?;

    credentials.envelope = view.envelope.to_vec();
    credentials.masking_key.copy_from_slice(view.masking_key);
    credentials
        .initiator_public_key
        .copy_from_slice(view.initiator_public_key);
    credentials.registered = true;

    Ok(())
}
