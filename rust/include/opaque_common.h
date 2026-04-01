#pragma once
#include "opaque_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Version ─────────────────────────────────────────────────────────────── */

#define OPAQUE_API_VERSION_MAJOR 2
#define OPAQUE_API_VERSION_MINOR 0
#define OPAQUE_API_VERSION_PATCH 0
#define OPAQUE_LIBRARY_VERSION   "2.0.0"

/* ── Wire-size constants ──────────────────────────────────────────────────── */

#define OPAQUE_KE1_LENGTH                    1273
#define OPAQUE_KE2_LENGTH                    1377
#define OPAQUE_KE3_LENGTH                      65
#define OPAQUE_REGISTRATION_REQUEST_LENGTH     33
#define OPAQUE_REGISTRATION_RESPONSE_LENGTH    65
#define OPAQUE_REGISTRATION_RECORD_LENGTH     169
#define OPAQUE_SESSION_KEY_LENGTH              64
#define OPAQUE_MASTER_KEY_LENGTH               32
#define OPAQUE_OPRF_SEED_LENGTH                32
#define OPAQUE_PUBLIC_KEY_LENGTH               32
#define OPAQUE_PRIVATE_KEY_LENGTH              32
#define OPAQUE_KEM_PUBLIC_KEY_LENGTH         1184
#define OPAQUE_KEM_CIPHERTEXT_LENGTH         1088

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum {
    OPAQUE_SUCCESS                   =    0,
    OPAQUE_ERROR_INVALID_INPUT       =   -1,
    OPAQUE_ERROR_CRYPTO              =   -2,
    OPAQUE_ERROR_INVALID_FORMAT      =   -3,
    OPAQUE_ERROR_VALIDATION          =   -4,
    OPAQUE_ERROR_AUTH_FAILED         =   -5,
    OPAQUE_ERROR_INVALID_KEY         =   -6,
    OPAQUE_ERROR_ALREADY_REGISTERED  =   -7,
    OPAQUE_ERROR_ML_KEM              =   -8,
    OPAQUE_ERROR_INVALID_ENVELOPE    =   -9,
    OPAQUE_ERROR_UNSUPPORTED_VERSION =  -10,
    OPAQUE_ERROR_INTERNAL            =  -99,
    OPAQUE_ERROR_BUSY                = -100,
    OPAQUE_ERROR_CORRUPTED_RECORD    = -101
} OpaqueErrorCode;

/* ── Opaque handle types ─────────────────────────────────────────────────── */

typedef struct OpaqueAgentHandle OpaqueAgentHandle;
typedef struct OpaqueAgentStateHandle OpaqueAgentStateHandle;
typedef struct OpaqueRelayHandle OpaqueRelayHandle;
typedef struct OpaqueRelayKeypairHandle OpaqueRelayKeypairHandle;
typedef struct OpaqueRelayStateHandle OpaqueRelayStateHandle;

/* ── Library lifecycle ───────────────────────────────────────────────────── */

OPAQUE_API const char*     opaque_version(void);
OPAQUE_API OpaqueErrorCode opaque_init(void);
OPAQUE_API void            opaque_shutdown(void);

/* ── Error utilities ─────────────────────────────────────────────────────── */

OPAQUE_API const char* opaque_error_string(OpaqueErrorCode code);

#ifdef __cplusplus
}
#endif
