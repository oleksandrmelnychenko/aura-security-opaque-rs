# Relay (Server) FFI API Reference

C-compatible API for the server side of the Ecliptix Hybrid PQ-OPAQUE protocol.
Use from Go (cgo), Node.js (N-API), Python (ctypes/cffi), C, or any language
with C FFI support.

## Wire Sizes

| Constant | Bytes | Getter function |
|----------|------:|-----------------|
| `PUBLIC_KEY_LENGTH` | 32 | — |
| `PRIVATE_KEY_LENGTH` | 32 | — |
| `OPRF_SEED_LENGTH` | 32 | — |
| `REGISTRATION_REQUEST_WIRE_LENGTH` | 33 | `opaque_relay_get_registration_request_length()` |
| `REGISTRATION_RESPONSE_WIRE_LENGTH` | 65 | `opaque_relay_get_registration_response_length()` |
| `REGISTRATION_RECORD_LENGTH` | 169 | `opaque_relay_get_registration_record_length()` |
| `RESPONDER_CREDENTIALS_LENGTH` | 169 | `opaque_relay_get_credentials_length()` |
| `KE1_LENGTH` | 1273 | `opaque_relay_get_ke1_length()` |
| `KE2_LENGTH` | 1377 | `opaque_relay_get_ke2_length()` |
| `KE3_LENGTH` | 65 | `opaque_relay_get_ke3_length()` |
| `HASH_LENGTH` (session key) | 64 | — |
| `MASTER_KEY_LENGTH` | 32 | — |
| `KEM_CIPHERTEXT_LENGTH` | 1088 | `opaque_relay_get_kem_ciphertext_length()` |

## Return Codes

| Code | Meaning |
|-----:|---------|
| `0` | Success |
| `-1` | Invalid input parameter |
| `-5` | Authentication/protocol validation failed |
| `-7` | Account already registered |
| `-101` | Provided credentials record is malformed |
| `-99` | Internal panic (should never happen) |
| `-100` | Handle is busy (concurrent call rejected) |

## Thread Safety

Each handle carries an atomic busy flag. A second call on the same handle while
the first is still running returns `-100`. Different handles can be used
concurrently from different threads.

## Lifecycle

```text
┌─────────────────── SERVER SETUP ────────────────────┐
│                                                      │
│ OPTION A — Generate fresh keypair:                   │
│   opaque_relay_keypair_generate(&kp_handle)          │
│   opaque_relay_keypair_get_public_key(               │
│       kp_handle, &public_key[32], 32)                │
│   opaque_relay_create(kp_handle, &relay_handle)      │
│                                                      │
│ OPTION B — Restore from stored keys:                 │
│   opaque_relay_create_with_keys(                     │
│       private_key, 32,                               │
│       public_key, 32,                                │
│       oprf_seed, 32,                                 │
│       &relay_handle)                                 │
└──────────────────────────────────────────────────────┘

┌────────── REGISTRATION (when client signs up) ──────┐
│                                                      │
│ ◄─── receive request[33] + account_id from client    │
│                                                      │
│ opaque_relay_create_registration_response(            │
│     relay_handle,                                    │
│     request, 33,                                     │
│     account_id, account_id_len,                      │
│     &response[65], 65)                               │
│                                                      │
│ ──── send response[65] to client ────►               │
│ ◄─── receive record[169] from client                 │
│                                                      │
│ opaque_relay_build_credentials(                       │
│     record, 169, &credentials[169], 169)             │
│                                                      │
│ Store credentials[169] in DB keyed by account_id     │
└──────────────────────────────────────────────────────┘

┌────────── AUTHENTICATION (each login) ──────────────┐
│                                                      │
│ ◄─── receive ke1[1273] + account_id from client      │
│                                                      │
│ Load credentials[169] from DB (required)             │
│                                                      │
│ opaque_relay_state_create(&state_handle)              │
│                                                      │
│ opaque_relay_generate_ke2(                           │
│     relay_handle,                                    │
│     ke1, 1273,                                       │
│     account_id, account_id_len,                      │
│     credentials, 169,                                │
│     &ke2[1377], 1377,                                │
│     state_handle)                                    │
│                                                      │
│ ──── send ke2[1377] to client ────►                  │
│ ◄─── receive ke3[65] from client                     │
│                                                      │
│ opaque_relay_finish(                                 │
│     relay_handle,                                    │
│     ke3, 65,                                         │
│     state_handle,                                    │
│     &session_key[64], 64,                            │
│     &master_key[32], 32)                             │
│                                                      │
│ opaque_relay_state_destroy(&state_handle)             │
└──────────────────────────────────────────────────────┘

┌─────────────────── CLEANUP ─────────────────────────┐
│ opaque_relay_destroy(&relay_handle)                   │
│ opaque_relay_keypair_destroy(&kp_handle)              │
└─────────────────────────────────────────────────────┘
```

## Functions

### opaque_relay_keypair_generate

```c
int32_t opaque_relay_keypair_generate(void **handle);
```

Generates a fresh Ristretto255 keypair and a random 32-byte OPRF seed.

| Parameter | Type | Description |
|-----------|------|-------------|
| `handle` | `void **` | Receives the new keypair handle (out) |

**Returns:** `0` on success.

**Ownership:** Caller owns the handle. Free with `opaque_relay_keypair_destroy`.

**Important:** The private key and OPRF seed must be persisted securely (vault, HSM)
if the server needs to survive restarts. Use `opaque_relay_create_with_keys` to restore.

---

### opaque_relay_keypair_destroy

```c
void opaque_relay_keypair_destroy(void **handle_ptr);
```

Destroys a keypair handle, securely zeroizing the private key and OPRF seed.
Sets `*handle_ptr` to NULL.

---

### opaque_relay_keypair_try_destroy

```c
int32_t opaque_relay_keypair_try_destroy(void **handle_ptr);
```

Tries to destroy a keypair handle and reports the outcome.

**Returns:**
- `0` on success (or already NULL).
- `-1` if `handle_ptr` is NULL.
- `-100` if the handle is currently busy.

Use this in production cleanup paths where silent destroy failure is unacceptable.

---

### opaque_relay_keypair_get_public_key

```c
int32_t opaque_relay_keypair_get_public_key(
    void    *handle,
    uint8_t *public_key,
    size_t   key_buffer_size
);
```

Copies the 32-byte public key into the provided buffer. This key must be
distributed to all clients (pinned in app binary or served over TLS).

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `handle` | `void *` | — | Keypair handle |
| `public_key` | `uint8_t *` | >= 32 | Output buffer |
| `key_buffer_size` | `size_t` | — | Must be >= 32 |

**Returns:** `0` on success.

---

### opaque_relay_create

```c
int32_t opaque_relay_create(
    void  *keypair_handle,
    void **handle
);
```

Creates a relay handle from a previously generated keypair. The relay handle is
the main server-side object used for registration and authentication.

| Parameter | Type | Description |
|-----------|------|-------------|
| `keypair_handle` | `void *` | Keypair from `opaque_relay_keypair_generate` |
| `handle` | `void **` | Receives the new relay handle (out) |

**Returns:** `0` on success. Free with `opaque_relay_destroy`.

---

### opaque_relay_create_with_keys

```c
int32_t opaque_relay_create_with_keys(
    const uint8_t *private_key,
    size_t         private_key_len,
    const uint8_t *public_key,
    size_t         public_key_len,
    const uint8_t *oprf_seed_ptr,
    size_t         oprf_seed_len,
    void         **handle
);
```

Creates a relay handle from pre-existing key material (for server restarts).
All three components must be the same ones used during registration.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `private_key` | `const uint8_t *` | 32 | Ristretto255 private key (scalar) |
| `private_key_len` | `size_t` | — | Must be exactly 32 |
| `public_key` | `const uint8_t *` | 32 | Ristretto255 public key (compressed point) |
| `public_key_len` | `size_t` | — | Must be exactly 32 |
| `oprf_seed_ptr` | `const uint8_t *` | 32 | OPRF seed for per-account key derivation |
| `oprf_seed_len` | `size_t` | — | Must be exactly 32 |
| `handle` | `void **` | — | Receives the new relay handle (out) |

**Returns:** `0` on success, `-1` if sizes are wrong, `-5` if key material is rejected.
Free with `opaque_relay_destroy`.

---

### opaque_relay_destroy

```c
void opaque_relay_destroy(void **handle_ptr);
```

Destroys a relay handle, securely zeroizing the private key and OPRF state.
Sets `*handle_ptr` to NULL.

---

### opaque_relay_try_destroy

```c
int32_t opaque_relay_try_destroy(void **handle_ptr);
```

Tries to destroy a relay handle and reports the outcome.

**Returns:**
- `0` on success (or already NULL).
- `-1` if `handle_ptr` is NULL.
- `-100` if the handle is currently busy.

Use this in production cleanup paths where silent destroy failure is unacceptable.

---

### opaque_relay_state_create

```c
int32_t opaque_relay_state_create(void **handle);
```

Allocates a fresh state for one authentication session.
Each login attempt requires its own state. **The state expires after 5 minutes.**

**Returns:** `0` on success. Free with `opaque_relay_state_destroy`.

---

### opaque_relay_state_destroy

```c
void opaque_relay_state_destroy(void **handle_ptr);
```

Destroys a state handle, securely zeroizing session keys and ephemeral material.

---

### opaque_relay_state_try_destroy

```c
int32_t opaque_relay_state_try_destroy(void **handle_ptr);
```

Tries to destroy a relay state handle and reports the outcome.

**Returns:**
- `0` on success (or already NULL).
- `-1` if `handle_ptr` is NULL.
- `-100` if the handle is currently busy.

Use this in production cleanup paths where silent destroy failure is unacceptable.

---

### opaque_relay_create_registration_response

```c
int32_t opaque_relay_create_registration_response(
    const void    *relay_handle,
    const uint8_t *request_data,
    size_t         request_length,
    const uint8_t *account_id,
    size_t         account_id_length,
    uint8_t       *response_data,
    size_t         response_buffer_size
);
```

**Registration step (server side).** Evaluates the client's blinded OPRF request.

The 65-byte response contains a version prefix (1 byte), the OPRF-evaluated
element (32 bytes), and the server's static public key (32 bytes).

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `relay_handle` | `const void *` | — | Relay handle |
| `request_data` | `const uint8_t *` | 33 | Client's blinded registration request |
| `request_length` | `size_t` | — | Must be exactly 33 |
| `account_id` | `const uint8_t *` | >= 1 | Unique account identifier (e.g., email) |
| `account_id_length` | `size_t` | — | Length of account_id in bytes |
| `response_data` | `uint8_t *` | >= 65 | Output buffer for registration response |
| `response_buffer_size` | `size_t` | — | Must be >= 65 |

**Returns:** `0` on success. Send the 65-byte response back to the client.

---

### opaque_relay_build_credentials

```c
int32_t opaque_relay_build_credentials(
    const uint8_t *registration_record,
    size_t         record_length,
    uint8_t       *credentials_out,
    size_t         credentials_out_length
);
```

Parses a 169-byte registration record into credentials for use in authentication.
Call after receiving the record from the client and before storing.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `registration_record` | `const uint8_t *` | 169 | Record received from client |
| `record_length` | `size_t` | — | Must be exactly 169 |
| `credentials_out` | `uint8_t *` | >= 169 | Output buffer for parsed credentials |
| `credentials_out_length` | `size_t` | — | Must be >= 169 |

**Returns:** `0` on success. Returns `-7` if the account is already registered.

Store the 169-byte credentials in the database keyed by account_id.
Pass them to `opaque_relay_generate_ke2` during authentication.

---

### opaque_relay_generate_ke2

```c
int32_t opaque_relay_generate_ke2(
    const void    *relay_handle,
    const uint8_t *ke1_data,
    size_t         ke1_length,
    const uint8_t *account_id,
    size_t         account_id_length,
    const uint8_t *credentials_data,
    size_t         credentials_length,
    uint8_t       *ke2_data,
    size_t         ke2_buffer_size,
    void          *state_handle
);
```

**Authentication step 1/2 (server side).** Processes the client's KE1 and produces KE2.

This step:
1. Evaluates the OPRF on the client's blinded request
2. Generates an ephemeral Ristretto255 keypair and nonce
3. Performs 4-way Diffie-Hellman
4. Encapsulates a shared secret via ML-KEM-768
5. Combines classical and post-quantum key material (AND-model)
6. Computes the server's MAC for mutual authentication

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `relay_handle` | `const void *` | — | Relay handle |
| `ke1_data` | `const uint8_t *` | 1273 | Client's KE1 message |
| `ke1_length` | `size_t` | — | Must be exactly 1273 |
| `account_id` | `const uint8_t *` | >= 1 | Account identifier for OPRF key derivation |
| `account_id_length` | `size_t` | — | Length of account_id |
| `credentials_data` | `const uint8_t *` | 169 / 0 | Stored credentials, or `NULL` for unknown user |
| `credentials_length` | `size_t` | — | Must be exactly 169, or 0 for unknown user |
| `ke2_data` | `uint8_t *` | >= 1377 | Output buffer for KE2 message |
| `ke2_buffer_size` | `size_t` | — | Must be >= 1377 |
| `state_handle` | `void *` | — | Fresh state from `opaque_relay_state_create` |

**Returns:** `0` on success. Send the 1377-byte KE2 to the client.
Pass `NULL, 0` for unknown users; the relay will derive deterministic fake credentials
and still emit a valid KE2 to reduce account-enumeration signals.
Returns `-101` when a non-null `credentials_data` buffer is malformed or invalid.

---

### opaque_relay_finish

```c
int32_t opaque_relay_finish(
    const void    *relay_handle,
    const uint8_t *ke3_data,
    size_t         ke3_length,
    void          *state_handle,
    uint8_t       *session_key,
    size_t         session_key_buffer_size,
    uint8_t       *master_key_out,
    size_t         master_key_buffer_size
);
```

**Authentication step 2/2 (server side).** Verifies the client's KE3 MAC and
extracts the session key and master key.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `relay_handle` | `const void *` | — | Relay handle (reserved, pass handle) |
| `ke3_data` | `const uint8_t *` | 65 | Client's KE3 message |
| `ke3_length` | `size_t` | — | Must be exactly 65 |
| `state_handle` | `void *` | — | Same state used in `generate_ke2` |
| `session_key` | `uint8_t *` | >= 64 | Output: 64-byte session key |
| `session_key_buffer_size` | `size_t` | — | Must be >= 64 |
| `master_key_out` | `uint8_t *` | >= 32 | Output: 32-byte master key |
| `master_key_buffer_size` | `size_t` | — | Must be >= 32 |

**Returns:** `0` on success (client authenticated). Returns `-5` if the client's
MAC is invalid (wrong password or tampered KE3). All ephemeral state is securely
zeroized after this call.

---

## Getter Functions

Use these to allocate buffers dynamically instead of hardcoding sizes.

| Function | Returns |
|----------|---------|
| `opaque_relay_get_ke1_length()` | 1273 |
| `opaque_relay_get_ke2_length()` | 1377 |
| `opaque_relay_get_ke3_length()` | 65 |
| `opaque_relay_get_registration_record_length()` | 169 |
| `opaque_relay_get_registration_request_length()` | 33 |
| `opaque_relay_get_registration_response_length()` | 65 |
| `opaque_relay_get_credentials_length()` | 169 |
| `opaque_relay_get_kem_ciphertext_length()` | 1088 |

## Go Example

```go
package main

/*
#cgo LDFLAGS: -lopaque_ffi
#include <stdint.h>
#include <stdlib.h>

extern int32_t opaque_relay_keypair_generate(void **handle);
extern int32_t opaque_relay_keypair_get_public_key(void *handle, uint8_t *pk, size_t len);
extern int32_t opaque_relay_create(void *kp, void **handle);
extern void    opaque_relay_keypair_destroy(void **handle);
extern int32_t opaque_relay_keypair_try_destroy(void **handle);
extern int32_t opaque_relay_state_create(void **handle);
extern void    opaque_relay_state_destroy(void **handle);
extern int32_t opaque_relay_state_try_destroy(void **handle);
extern void    opaque_relay_destroy(void **handle);
extern int32_t opaque_relay_try_destroy(void **handle);
extern int32_t opaque_relay_create_registration_response(
    const void *relay, const uint8_t *req, size_t req_len,
    const uint8_t *aid, size_t aid_len, uint8_t *resp, size_t resp_len);
extern int32_t opaque_relay_build_credentials(
    const uint8_t *record, size_t record_len, uint8_t *creds, size_t creds_len);
extern int32_t opaque_relay_generate_ke2(
    const void *relay, const uint8_t *ke1, size_t ke1_len,
    const uint8_t *aid, size_t aid_len,
    const uint8_t *creds, size_t creds_len,
    uint8_t *ke2, size_t ke2_len, void *state);
extern int32_t opaque_relay_finish(
    const void *relay, const uint8_t *ke3, size_t ke3_len,
    void *state, uint8_t *sk, size_t sk_len, uint8_t *mk, size_t mk_len);
extern size_t opaque_relay_get_ke2_length();
extern size_t opaque_relay_get_registration_request_length();
extern size_t opaque_relay_get_registration_response_length();
extern size_t opaque_relay_get_registration_record_length();
extern size_t opaque_relay_get_credentials_length();
*/
import "C"
import "unsafe"

func main() {
    // Setup
    var kpHandle unsafe.Pointer
    C.opaque_relay_keypair_generate(&kpHandle)
    defer C.opaque_relay_keypair_try_destroy(&kpHandle)

    publicKey := make([]byte, 32)
    C.opaque_relay_keypair_get_public_key(kpHandle,
        (*C.uint8_t)(&publicKey[0]), 32)

    var relayHandle unsafe.Pointer
    C.opaque_relay_create(kpHandle, &relayHandle)
    defer C.opaque_relay_try_destroy(&relayHandle)

    // --- Registration ---
    // request comes from client (33 bytes)
    accountID := []byte("user@example.com")
    response := make([]byte, C.opaque_relay_get_registration_response_length())

    C.opaque_relay_create_registration_response(
        relayHandle,
        (*C.uint8_t)(&request[0]), C.size_t(len(request)),
        (*C.uint8_t)(&accountID[0]), C.size_t(len(accountID)),
        (*C.uint8_t)(&response[0]), C.size_t(len(response)))

    // ... send response to client, receive record (169 bytes) ...

    credentials := make([]byte, C.opaque_relay_get_credentials_length())
    C.opaque_relay_build_credentials(
        (*C.uint8_t)(&record[0]), C.size_t(len(record)),
        (*C.uint8_t)(&credentials[0]), C.size_t(len(credentials)))

    // Store credentials in database keyed by accountID

    // --- Authentication ---
    // ke1 comes from client (1273 bytes)
    var stateHandle unsafe.Pointer
    C.opaque_relay_state_create(&stateHandle)
    defer C.opaque_relay_state_try_destroy(&stateHandle)

    ke2 := make([]byte, C.opaque_relay_get_ke2_length())
    C.opaque_relay_generate_ke2(
        relayHandle,
        (*C.uint8_t)(&ke1[0]), C.size_t(len(ke1)),
        (*C.uint8_t)(&accountID[0]), C.size_t(len(accountID)),
        (*C.uint8_t)(&credentials[0]), C.size_t(len(credentials)),
        (*C.uint8_t)(&ke2[0]), C.size_t(len(ke2)),
        stateHandle)

    // ... send ke2 to client, receive ke3 (65 bytes) ...

    sessionKey := make([]byte, 64)
    masterKey := make([]byte, 32)
    rc := C.opaque_relay_finish(
        relayHandle,
        (*C.uint8_t)(&ke3[0]), C.size_t(len(ke3)),
        stateHandle,
        (*C.uint8_t)(&sessionKey[0]), 64,
        (*C.uint8_t)(&masterKey[0]), 32)

    if rc == 0 {
        // Authentication successful — sessionKey and masterKey are shared with client
    }
}
```
