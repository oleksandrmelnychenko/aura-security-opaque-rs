# Agent (Client) FFI API Reference

C-compatible API for the client side of the Ecliptix Hybrid PQ-OPAQUE protocol.
Use from Swift, Kotlin, C, Go, or any language with C FFI support.

All functions return integer error codes directly. Use `opaque_error_string()`
for a stable human-readable description of a code.

## Wire Sizes

| Constant | Bytes | Getter function |
|----------|------:|-----------------|
| `PUBLIC_KEY_LENGTH` | 32 | — |
| `REGISTRATION_REQUEST_WIRE_LENGTH` | 33 | `opaque_get_registration_request_length()` |
| `REGISTRATION_RESPONSE_WIRE_LENGTH` | 65 | `opaque_get_registration_response_length()` |
| `REGISTRATION_RECORD_LENGTH` | 169 | `opaque_get_registration_record_length()` |
| `KE1_LENGTH` | 1273 | `opaque_get_ke1_length()` |
| `KE2_LENGTH` | 1377 | `opaque_get_ke2_length()` |
| `KE3_LENGTH` | 65 | `opaque_get_ke3_length()` |
| `HASH_LENGTH` (session key) | 64 | — |
| `MASTER_KEY_LENGTH` | 32 | — |
| `KEM_PUBLIC_KEY_LENGTH` | 1184 | `opaque_get_kem_public_key_length()` |
| `KEM_CIPHERTEXT_LENGTH` | 1088 | `opaque_get_kem_ciphertext_length()` |

## Return Codes

| Code | Meaning |
|-----:|---------|
| `0` | Success |
| `-1` | Invalid input parameter |
| `-5` | Authentication/protocol validation failed |
| `-7` | Account already registered |
| `-99` | Internal panic (should never happen) |
| `-100` | Handle is busy (concurrent call rejected) |

## Thread Safety

Each handle carries an atomic busy flag. A second call on the same handle while
the first is still running returns `-100`. Different handles can be used
concurrently from different threads.

## Lifecycle

```text
┌─────────────────────── SETUP ───────────────────────┐
│ opaque_init()                                       │
│ opaque_agent_create(relay_pk, 32, &handle)          │
│ opaque_agent_state_create(&state)                   │
└─────────────────────────────────────────────────────┘

┌─────────────── REGISTRATION (one-time) ─────────────┐
│ opaque_agent_create_registration_request(            │
│     handle, password, password_len,                  │
│     state, &request[33], 33)                         │
│                                                      │
│         ──── send request[33] to server ────►        │
│         ◄─── receive response[65] ──────────         │
│                                                      │
│ opaque_agent_finalize_registration(                  │
│     handle, response, 65, state, &record[169], 169)  │
│                                                      │
│         ──── send record[169] to server ────►        │
└──────────────────────────────────────────────────────┘

┌─────────────── AUTHENTICATION (each login) ─────────┐
│ opaque_agent_state_create(&state)   // fresh state   │
│                                                      │
│ opaque_agent_generate_ke1(                           │
│     handle, password, password_len,                  │
│     account_id, account_id_len,                      │
│     state, &ke1[1273], 1273)                         │
│                                                      │
│         ──── send ke1[1273] to server ────►          │
│         ◄─── receive ke2[1377] ──────────            │
│                                                      │
│ opaque_agent_generate_ke3(                           │
│     handle, ke2, 1377, state, &ke3[65], 65)          │
│                                                      │
│         ──── send ke3[65] to server ────►            │
│                                                      │
│ opaque_agent_finish(                                 │
│     handle, state,                                   │
│     &session_key[64], 64,                            │
│     &master_key[32], 32)                             │
└──────────────────────────────────────────────────────┘

┌─────────────────── CLEANUP ─────────────────────────┐
│ opaque_agent_state_destroy(&state)                   │
│ opaque_agent_destroy(&handle)                        │
└─────────────────────────────────────────────────────┘
```

## Functions

### opaque_init

```c
int32_t opaque_init(void);
```

Initializes the OPAQUE library. Must be called once before any other function.

**Returns:** `0` on success.

---

### opaque_agent_create

```c
int32_t opaque_agent_create(
    const uint8_t *relay_public_key,
    size_t         key_length,
    void         **handle
);
```

Creates a new agent handle bound to a specific relay's public key.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `relay_public_key` | `const uint8_t *` | 32 | Relay's static Ristretto255 public key |
| `key_length` | `size_t` | — | Must be exactly 32 |
| `handle` | `void **` | — | Receives the new agent handle (out) |

**Returns:** `0` on success, `-1` if inputs are invalid, `-5` if key material is rejected.

**Ownership:** Caller owns the handle. Free with `opaque_agent_destroy`.

---

### opaque_agent_destroy

```c
void opaque_agent_destroy(void **handle_ptr);
```

Destroys an agent handle, securely zeroizing all key material.
Sets `*handle_ptr` to NULL. Calling on an already-null pointer is a no-op.

---

### opaque_agent_try_destroy

```c
int32_t opaque_agent_try_destroy(void **handle_ptr);
```

Tries to destroy an agent handle and reports the outcome.

**Returns:**
- `0` on success (or already NULL).
- `-1` if `handle_ptr` is NULL.
- `-100` if the handle is currently busy.

Use this in production cleanup paths where silent destroy failure is unacceptable.

---

### opaque_agent_state_create

```c
int32_t opaque_agent_state_create(void **handle);
```

Allocates a fresh state for one registration or authentication session.
Each protocol flow requires its own state. **The state expires after 5 minutes**.

**Returns:** `0` on success. Free with `opaque_agent_state_destroy`.

---

### opaque_agent_state_destroy

```c
void opaque_agent_state_destroy(void **handle_ptr);
```

Destroys a state handle, securely zeroizing password, keys, nonces, and shared secrets.

---

### opaque_agent_state_try_destroy

```c
int32_t opaque_agent_state_try_destroy(void **handle_ptr);
```

Tries to destroy a state handle and reports the outcome.

**Returns:**
- `0` on success (or already NULL).
- `-1` if `handle_ptr` is NULL.
- `-100` if the handle is currently busy.

Use this in production cleanup paths where silent destroy failure is unacceptable.

---

### opaque_agent_create_registration_request

```c
int32_t opaque_agent_create_registration_request(
    void          *agent_handle,
    const uint8_t *secure_key,
    size_t         secure_key_length,
    void          *state_handle,
    uint8_t       *request_out,
    size_t         request_length
);
```

**Registration step 1/2.** Creates an OPRF-blinded registration request from the user's password.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `agent_handle` | `void *` | — | Agent handle from `opaque_agent_create` |
| `secure_key` | `const uint8_t *` | 1–4096 | User's password (raw bytes) |
| `secure_key_length` | `size_t` | — | Length of password in bytes |
| `state_handle` | `void *` | — | Fresh state from `opaque_agent_state_create` |
| `request_out` | `uint8_t *` | >= 33 | Output buffer for the blinded request |
| `request_length` | `size_t` | — | Size of output buffer (must be >= 33) |

**Returns:** `0` on success. The 33-byte request is written to `request_out`.
Send this request to the server.

---

### opaque_agent_finalize_registration

```c
int32_t opaque_agent_finalize_registration(
    void          *agent_handle,
    const uint8_t *response,
    size_t         response_length,
    void          *state_handle,
    uint8_t       *record_out,
    size_t         record_length
);
```

**Registration step 2/2.** Finalizes registration by creating an encrypted envelope.

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `agent_handle` | `void *` | — | Agent handle from `opaque_agent_create` |
| `response` | `const uint8_t *` | 65 | Server's registration response |
| `response_length` | `size_t` | — | Must be exactly 65 |
| `state_handle` | `void *` | — | Same state used in step 1 |
| `record_out` | `uint8_t *` | >= 169 | Output buffer for the registration record |
| `record_length` | `size_t` | — | Size of output buffer (must be >= 169) |

**Returns:** `0` on success. The 169-byte record is written to `record_out`.
Send this record to the server for storage. Returns `-5` if the server's public
key does not match the one given at agent creation (MITM protection).

---

### opaque_agent_generate_ke1

```c
int32_t opaque_agent_generate_ke1(
    void          *agent_handle,
    const uint8_t *secure_key,
    size_t         secure_key_length,
    const uint8_t *account_id,
    size_t         account_id_length,
    void          *state_handle,
    uint8_t       *ke1_out,
    size_t         ke1_length
);
```

**Authentication step 1/3.** Generates the first key-exchange message (KE1).

The 1273-byte KE1 contains:
- Protocol version prefix (1 byte)
- OPRF-blinded credential request (32 bytes)
- Ephemeral Ristretto255 public key (32 bytes)
- Random nonce (24 bytes)
- Ephemeral ML-KEM-768 public key (1184 bytes)

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `agent_handle` | `void *` | — | Agent handle |
| `secure_key` | `const uint8_t *` | 1–4096 | User's password (raw bytes) |
| `secure_key_length` | `size_t` | — | Length of password |
| `account_id` | `const uint8_t *` | 1-1024 | Account identifier bound into transcript |
| `account_id_length` | `size_t` | — | Length of account identifier |
| `state_handle` | `void *` | — | Fresh state from `opaque_agent_state_create` |
| `ke1_out` | `uint8_t *` | >= 1273 | Output buffer for KE1 |
| `ke1_length` | `size_t` | — | Size of output buffer (must be >= 1273) |

**Returns:** `0` on success. Send the 1273-byte KE1 to the server along with the same `account_id`.
The server must use the exact same `account_id` in `opaque_relay_generate_ke2`, because this value
is cryptographically bound into the handshake transcript.

---

### opaque_agent_generate_ke3

```c
int32_t opaque_agent_generate_ke3(
    void          *agent_handle,
    const uint8_t *ke2,
    size_t         ke2_length,
    void          *state_handle,
    uint8_t       *ke3_out,
    size_t         ke3_length
);
```

**Authentication step 2/3.** Processes the server's KE2 and produces KE3.

This step:
1. Unblinds the OPRF output and derives the randomized password via Argon2id
2. Decrypts the envelope to recover the client's static keys
3. Performs 4-way Diffie-Hellman
4. Decapsulates the ML-KEM-768 ciphertext
5. Combines classical and post-quantum key material (AND-model)
6. Verifies the server's MAC (mutual authentication)
7. Computes the client's MAC for the server to verify

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `agent_handle` | `void *` | — | Agent handle |
| `ke2` | `const uint8_t *` | 1377 | Server's KE2 message |
| `ke2_length` | `size_t` | — | Must be exactly 1377 |
| `state_handle` | `void *` | — | Same state used in `generate_ke1` |
| `ke3_out` | `uint8_t *` | >= 65 | Output buffer for KE3 |
| `ke3_length` | `size_t` | — | Size of output buffer (must be >= 65) |

**Returns:** `0` on success. Returns `-5` if authentication fails (wrong password or tampered KE2).
Send the 65-byte KE3 to the server.

---

### opaque_agent_finish

```c
int32_t opaque_agent_finish(
    void    *agent_handle,
    void    *state_handle,
    uint8_t *session_key_out,
    size_t   session_key_length,
    uint8_t *master_key_out,
    size_t   master_key_length
);
```

**Authentication step 3/3.** Extracts the session key and master key.

Call after `opaque_agent_generate_ke3` succeeds. Both keys are identical on
client and server, suitable for symmetric encryption (AES-GCM, ChaCha20-Poly1305, etc.).

| Parameter | Type | Size | Description |
|-----------|------|------|-------------|
| `agent_handle` | `void *` | — | Agent handle (reserved, pass handle) |
| `state_handle` | `void *` | — | Same state used in `generate_ke3` |
| `session_key_out` | `uint8_t *` | >= 64 | Output: 64-byte session key |
| `session_key_length` | `size_t` | — | Must be >= 64 |
| `master_key_out` | `uint8_t *` | >= 32 | Output: 32-byte master key |
| `master_key_length` | `size_t` | — | Must be >= 32 |

**Returns:** `0` on success. All sensitive state is securely zeroized after this call.

---

## Getter Functions

Use these to allocate buffers dynamically instead of hardcoding sizes.

| Function | Returns |
|----------|---------|
| `opaque_get_ke1_length()` | 1273 |
| `opaque_get_ke2_length()` | 1377 |
| `opaque_get_ke3_length()` | 65 |
| `opaque_get_registration_record_length()` | 169 |
| `opaque_get_registration_request_length()` | 33 |
| `opaque_get_registration_response_length()` | 65 |
| `opaque_get_kem_public_key_length()` | 1184 |
| `opaque_get_kem_ciphertext_length()` | 1088 |

## Swift Example

```swift
import Foundation

// Setup
opaque_init()

var agentHandle: UnsafeMutableRawPointer?
let relayPk: [UInt8] = ... // 32 bytes from server
opaque_agent_create(relayPk, relayPk.count, &agentHandle)

// --- Registration (one-time) ---

var stateHandle: UnsafeMutableRawPointer?
opaque_agent_state_create(&stateHandle)

let password = Array("hunter2".utf8)
var request = [UInt8](repeating: 0, count: Int(opaque_get_registration_request_length()))
opaque_agent_create_registration_request(
    agentHandle, password, password.count,
    stateHandle, &request, request.count)

// ... send request to server, receive response (65 bytes) ...

var record = [UInt8](repeating: 0, count: Int(opaque_get_registration_record_length()))
opaque_agent_finalize_registration(
    agentHandle, response, response.count,
    stateHandle, &record, record.count)

// ... send record to server for storage ...
opaque_agent_state_destroy(&stateHandle)

// --- Authentication (each login) ---

opaque_agent_state_create(&stateHandle)

var ke1 = [UInt8](repeating: 0, count: Int(opaque_get_ke1_length()))
opaque_agent_generate_ke1(
    agentHandle, password, password.count,
    accountID, accountID.count,
    stateHandle, &ke1, ke1.count)

// ... send ke1 to server, receive ke2 (1377 bytes) ...

var ke3 = [UInt8](repeating: 0, count: Int(opaque_get_ke3_length()))
opaque_agent_generate_ke3(
    agentHandle, ke2, ke2.count,
    stateHandle, &ke3, ke3.count)

// ... send ke3 to server ...

var sessionKey = [UInt8](repeating: 0, count: 64)
var masterKey  = [UInt8](repeating: 0, count: 32)
opaque_agent_finish(
    agentHandle, stateHandle,
    &sessionKey, 64, &masterKey, 32)

// Cleanup
let stateDestroyRc = opaque_agent_state_try_destroy(&stateHandle)
let agentDestroyRc = opaque_agent_try_destroy(&agentHandle)
// Optionally handle `-100` by retrying cleanup from a safe point.
```
