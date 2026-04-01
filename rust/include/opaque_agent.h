#pragma once
#include "opaque_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Agent (client-side) API.
 *
 * Handles are caller-owned. Destroy them with the matching destroy function.
 * A single handle must not be used concurrently; concurrent calls return
 * OPAQUE_ERROR_BUSY.
 */

/* ── Handle management ───────────────────────────────────────────────────── */

OPAQUE_API OpaqueErrorCode opaque_agent_create(
    const uint8_t*       relay_public_key,
    size_t               key_length,
    OpaqueAgentHandle**  out_handle);

OPAQUE_API void opaque_agent_destroy(OpaqueAgentHandle** handle_ptr);

OPAQUE_API OpaqueErrorCode opaque_agent_try_destroy(
    OpaqueAgentHandle** handle_ptr);

OPAQUE_API OpaqueErrorCode opaque_agent_state_create(
    OpaqueAgentStateHandle** out_handle);

OPAQUE_API void opaque_agent_state_destroy(OpaqueAgentStateHandle** handle_ptr);

OPAQUE_API OpaqueErrorCode opaque_agent_state_try_destroy(
    OpaqueAgentStateHandle** handle_ptr);

/* ── Registration ────────────────────────────────────────────────────────── */

OPAQUE_API OpaqueErrorCode opaque_agent_create_registration_request(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          password,
    size_t                  password_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                request_out,
    size_t                  request_length);

OPAQUE_API OpaqueErrorCode opaque_agent_finalize_registration(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          response,
    size_t                  response_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                record_out,
    size_t                  record_length);

/* ── Authentication ──────────────────────────────────────────────────────── */

/*
 * `account_id` is bound into the transcript and must match the relay-side
 * account identifier exactly. Valid lengths are 1..=1024 bytes.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_generate_ke1(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          password,
    size_t                  password_length,
    const uint8_t*          account_id,
    size_t                  account_id_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                ke1_out,
    size_t                  ke1_length);

OPAQUE_API OpaqueErrorCode opaque_agent_generate_ke3(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          ke2,
    size_t                  ke2_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                ke3_out,
    size_t                  ke3_length);

OPAQUE_API OpaqueErrorCode opaque_agent_finish(
    OpaqueAgentHandle*      agent_handle,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                session_key_out,
    size_t                  session_key_length,
    uint8_t*                master_key_out,
    size_t                  master_key_length);

/* ── Wire-size queries ───────────────────────────────────────────────────── */

OPAQUE_API size_t opaque_get_ke1_length(void);
OPAQUE_API size_t opaque_get_ke2_length(void);
OPAQUE_API size_t opaque_get_ke3_length(void);
OPAQUE_API size_t opaque_get_registration_record_length(void);
OPAQUE_API size_t opaque_get_registration_request_length(void);
OPAQUE_API size_t opaque_get_registration_response_length(void);
OPAQUE_API size_t opaque_get_kem_public_key_length(void);
OPAQUE_API size_t opaque_get_kem_ciphertext_length(void);

#ifdef __cplusplus
}
#endif
