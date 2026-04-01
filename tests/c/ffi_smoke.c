#include "opaque_api.h"

#include <stddef.h>
#include <stdint.h>

int main(void) {
    OpaqueAgentHandle *agent = NULL;
    OpaqueAgentStateHandle *state = NULL;
    uint8_t invalid_key[OPAQUE_PUBLIC_KEY_LENGTH] = {0};

    if (opaque_init() != OPAQUE_SUCCESS) {
        return 1;
    }

    if (opaque_get_ke1_length() != OPAQUE_KE1_LENGTH) {
        return 2;
    }

    if (opaque_relay_get_oprf_seed_length() != OPAQUE_OPRF_SEED_LENGTH) {
        return 3;
    }

    /* Expected failure: identity / zero public key is invalid. */
    if (opaque_agent_create(invalid_key, sizeof(invalid_key), &agent) == OPAQUE_SUCCESS) {
        opaque_agent_destroy(&agent);
        return 4;
    }

    opaque_agent_state_destroy(&state);
    opaque_agent_destroy(&agent);
    opaque_shutdown();
    return 0;
}
