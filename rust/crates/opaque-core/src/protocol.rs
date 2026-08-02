// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

use crate::types::{
    pq, OpaqueError, OpaqueResult, CREDENTIAL_RESPONSE_LENGTH, KE1_BASE_LENGTH, KE1_LENGTH,
    KE2_BASE_LENGTH, KE2_LENGTH, KE3_LENGTH, MAC_LENGTH, MASKING_KEY_LENGTH, NONCE_LENGTH,
    PROTOCOL_VERSION, PROTOCOL_VERSION_2, PUBLIC_KEY_LENGTH, REGISTRATION_CREDENTIAL_LENGTH,
    REGISTRATION_RECORD_LENGTH, REGISTRATION_REQUEST_LENGTH, REGISTRATION_REQUEST_WIRE_LENGTH,
    REGISTRATION_RESPONSE_WIRE_LENGTH, VERSION_PREFIX_LENGTH,
};

const V: usize = VERSION_PREFIX_LENGTH;

const REG_REQ_PAYLOAD_OFFSET: usize = V;

const REG_RESP_EVALUATED_OFFSET: usize = V;

const REG_RESP_RESPONDER_KEY_OFFSET: usize = V + REGISTRATION_REQUEST_LENGTH;

const REG_RECORD_MASKING_KEY_OFFSET: usize = V;

const REG_RECORD_ENVELOPE_OFFSET: usize = V + MASKING_KEY_LENGTH;

const REG_RECORD_INITIATOR_KEY_OFFSET: usize = V + REGISTRATION_CREDENTIAL_LENGTH;

const KE1_CRED_REQ_OFFSET: usize = V;

const KE1_INITIATOR_PK_OFFSET: usize = V + REGISTRATION_REQUEST_LENGTH;

const KE1_INITIATOR_NONCE_OFFSET: usize = V + REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH;

const KE1_PQ_PK_OFFSET: usize = V + KE1_BASE_LENGTH;

const KE2_RESP_NONCE_OFFSET: usize = V;

const KE2_RESP_PK_OFFSET: usize = V + NONCE_LENGTH;

const KE2_CRED_RESP_OFFSET: usize = V + NONCE_LENGTH + PUBLIC_KEY_LENGTH;

const KE2_RESP_MAC_OFFSET: usize =
    V + NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;

const KE2_KEM_CT_OFFSET: usize = V + KE2_BASE_LENGTH;

const KE3_MAC_OFFSET: usize = V;

fn check_version(data: &[u8]) -> OpaqueResult<()> {
    if data.is_empty() {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    match data[0] {
        PROTOCOL_VERSION_2 => Ok(()),
        _ => Err(OpaqueError::UnsupportedVersion),
    }
}

pub struct RegistrationResponseRef<'a> {
    pub evaluated_element: &'a [u8],

    pub responder_public_key: &'a [u8],
}

pub struct RegistrationRecordRef<'a> {
    pub masking_key: &'a [u8],

    pub envelope: &'a [u8],

    pub initiator_public_key: &'a [u8],
}

pub struct Ke1Ref<'a> {
    pub credential_request: &'a [u8],

    pub initiator_public_key: &'a [u8],

    pub initiator_nonce: &'a [u8],

    pub pq_ephemeral_public_key: &'a [u8],
}

pub struct Ke2Ref<'a> {
    pub responder_nonce: &'a [u8],

    pub responder_public_key: &'a [u8],

    pub credential_response: &'a [u8],

    pub responder_mac: &'a [u8],

    pub kem_ciphertext: &'a [u8],
}

pub struct Ke3Ref<'a> {
    pub initiator_mac: &'a [u8],
}

pub fn parse_registration_request(data: &[u8]) -> OpaqueResult<&[u8]> {
    if data.len() != REGISTRATION_REQUEST_WIRE_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(&data[REG_REQ_PAYLOAD_OFFSET..])
}

pub fn parse_registration_response(data: &[u8]) -> OpaqueResult<RegistrationResponseRef<'_>> {
    if data.len() != REGISTRATION_RESPONSE_WIRE_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(RegistrationResponseRef {
        evaluated_element: &data[REG_RESP_EVALUATED_OFFSET..REG_RESP_RESPONDER_KEY_OFFSET],
        responder_public_key: &data[REG_RESP_RESPONDER_KEY_OFFSET..],
    })
}

pub fn parse_registration_record(data: &[u8]) -> OpaqueResult<RegistrationRecordRef<'_>> {
    if data.len() != REGISTRATION_RECORD_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(RegistrationRecordRef {
        masking_key: &data[REG_RECORD_MASKING_KEY_OFFSET..REG_RECORD_ENVELOPE_OFFSET],
        envelope: &data[REG_RECORD_ENVELOPE_OFFSET..REG_RECORD_INITIATOR_KEY_OFFSET],
        initiator_public_key: &data[REG_RECORD_INITIATOR_KEY_OFFSET..],
    })
}

pub fn parse_ke1(data: &[u8]) -> OpaqueResult<Ke1Ref<'_>> {
    if data.len() != KE1_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(Ke1Ref {
        credential_request: &data[KE1_CRED_REQ_OFFSET..KE1_INITIATOR_PK_OFFSET],
        initiator_public_key: &data[KE1_INITIATOR_PK_OFFSET..KE1_INITIATOR_NONCE_OFFSET],
        initiator_nonce: &data[KE1_INITIATOR_NONCE_OFFSET..KE1_PQ_PK_OFFSET],
        pq_ephemeral_public_key: &data[KE1_PQ_PK_OFFSET..],
    })
}

pub fn parse_ke2(data: &[u8]) -> OpaqueResult<Ke2Ref<'_>> {
    if data.len() != KE2_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(Ke2Ref {
        responder_nonce: &data[KE2_RESP_NONCE_OFFSET..KE2_RESP_PK_OFFSET],
        responder_public_key: &data[KE2_RESP_PK_OFFSET..KE2_CRED_RESP_OFFSET],
        credential_response: &data[KE2_CRED_RESP_OFFSET..KE2_RESP_MAC_OFFSET],
        responder_mac: &data[KE2_RESP_MAC_OFFSET..KE2_KEM_CT_OFFSET],
        kem_ciphertext: &data[KE2_KEM_CT_OFFSET..],
    })
}

pub fn parse_ke3(data: &[u8]) -> OpaqueResult<Ke3Ref<'_>> {
    if data.len() != KE3_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    check_version(data)?;
    Ok(Ke3Ref {
        initiator_mac: &data[KE3_MAC_OFFSET..],
    })
}

pub fn write_registration_record(
    credential_storage: &[u8],
    initiator_public_key: &[u8],
    out: &mut [u8],
) -> OpaqueResult<()> {
    if credential_storage.len() != REGISTRATION_CREDENTIAL_LENGTH
        || initiator_public_key.len() != PUBLIC_KEY_LENGTH
        || out.len() < REGISTRATION_RECORD_LENGTH
    {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[REG_RECORD_MASKING_KEY_OFFSET..REG_RECORD_INITIATOR_KEY_OFFSET]
        .copy_from_slice(credential_storage);
    out[REG_RECORD_INITIATOR_KEY_OFFSET..REGISTRATION_RECORD_LENGTH]
        .copy_from_slice(initiator_public_key);
    Ok(())
}

pub fn write_ke1(
    credential_request: &[u8],
    initiator_public_key: &[u8],
    initiator_nonce: &[u8],
    pq_ephemeral_public_key: &[u8],
    out: &mut [u8],
) -> OpaqueResult<()> {
    if credential_request.len() != REGISTRATION_REQUEST_LENGTH
        || initiator_public_key.len() != PUBLIC_KEY_LENGTH
        || initiator_nonce.len() != NONCE_LENGTH
        || pq_ephemeral_public_key.len() != pq::KEM_PUBLIC_KEY_LENGTH
        || out.len() < KE1_LENGTH
    {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[KE1_CRED_REQ_OFFSET..KE1_INITIATOR_PK_OFFSET].copy_from_slice(credential_request);
    out[KE1_INITIATOR_PK_OFFSET..KE1_INITIATOR_NONCE_OFFSET].copy_from_slice(initiator_public_key);
    out[KE1_INITIATOR_NONCE_OFFSET..KE1_PQ_PK_OFFSET].copy_from_slice(initiator_nonce);
    out[KE1_PQ_PK_OFFSET..KE1_LENGTH].copy_from_slice(pq_ephemeral_public_key);
    Ok(())
}

pub fn write_ke2(
    responder_nonce: &[u8],
    responder_public_key: &[u8],
    credential_response: &[u8],
    responder_mac: &[u8],
    kem_ciphertext: &[u8],
    out: &mut [u8],
) -> OpaqueResult<()> {
    if responder_nonce.len() != NONCE_LENGTH
        || responder_public_key.len() != PUBLIC_KEY_LENGTH
        || credential_response.len() != CREDENTIAL_RESPONSE_LENGTH
        || responder_mac.len() != MAC_LENGTH
        || kem_ciphertext.len() != pq::KEM_CIPHERTEXT_LENGTH
        || out.len() < KE2_LENGTH
    {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[KE2_RESP_NONCE_OFFSET..KE2_RESP_PK_OFFSET].copy_from_slice(responder_nonce);
    out[KE2_RESP_PK_OFFSET..KE2_CRED_RESP_OFFSET].copy_from_slice(responder_public_key);
    out[KE2_CRED_RESP_OFFSET..KE2_RESP_MAC_OFFSET].copy_from_slice(credential_response);
    out[KE2_RESP_MAC_OFFSET..KE2_KEM_CT_OFFSET].copy_from_slice(responder_mac);
    out[KE2_KEM_CT_OFFSET..KE2_LENGTH].copy_from_slice(kem_ciphertext);
    Ok(())
}

pub fn write_ke3(initiator_mac: &[u8], out: &mut [u8]) -> OpaqueResult<()> {
    if initiator_mac.len() != MAC_LENGTH || out.len() < KE3_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[KE3_MAC_OFFSET..KE3_LENGTH].copy_from_slice(initiator_mac);
    Ok(())
}

pub fn write_registration_request(payload: &[u8], out: &mut [u8]) -> OpaqueResult<()> {
    if payload.len() != REGISTRATION_REQUEST_LENGTH || out.len() < REGISTRATION_REQUEST_WIRE_LENGTH
    {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[REG_REQ_PAYLOAD_OFFSET..REGISTRATION_REQUEST_WIRE_LENGTH].copy_from_slice(payload);
    Ok(())
}

pub fn write_registration_response(
    evaluated_element: &[u8],
    responder_public_key: &[u8],
    out: &mut [u8],
) -> OpaqueResult<()> {
    if evaluated_element.len() != REGISTRATION_REQUEST_LENGTH
        || responder_public_key.len() != PUBLIC_KEY_LENGTH
        || out.len() < REGISTRATION_RESPONSE_WIRE_LENGTH
    {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    out[0] = PROTOCOL_VERSION;
    out[REG_RESP_EVALUATED_OFFSET..REG_RESP_RESPONDER_KEY_OFFSET]
        .copy_from_slice(evaluated_element);
    out[REG_RESP_RESPONDER_KEY_OFFSET..REGISTRATION_RESPONSE_WIRE_LENGTH]
        .copy_from_slice(responder_public_key);
    Ok(())
}
