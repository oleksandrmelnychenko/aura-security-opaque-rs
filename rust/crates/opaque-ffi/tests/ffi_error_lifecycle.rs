use std::ffi::c_void;
use std::ptr;

use opaque_ffi as _;

unsafe extern "C" {
    fn opaque_relay_keypair_generate(handle: *mut *mut c_void) -> i32;
    fn opaque_relay_keypair_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_relay_keypair_get_public_key(
        handle: *mut c_void,
        public_key: *mut u8,
        key_buffer_size: usize,
    ) -> i32;
    fn opaque_relay_create(keypair_handle: *mut c_void, handle: *mut *mut c_void) -> i32;
    fn opaque_relay_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_relay_state_create(handle: *mut *mut c_void) -> i32;
    fn opaque_relay_state_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_relay_generate_ke2(
        relay_handle: *const c_void,
        ke1_data: *const u8,
        ke1_length: usize,
        account_id: *const u8,
        account_id_length: usize,
        credentials_data: *const u8,
        credentials_length: usize,
        ke2_data: *mut u8,
        ke2_buffer_size: usize,
        state_handle: *mut c_void,
    ) -> i32;

    fn opaque_agent_create(
        relay_public_key: *const u8,
        key_length: usize,
        out_handle: *mut *mut c_void,
    ) -> i32;
    fn opaque_agent_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_state_create(out_handle: *mut *mut c_void) -> i32;
    fn opaque_agent_state_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_generate_ke1(
        agent_handle: *mut c_void,
        password: *const u8,
        password_length: usize,
        account_id: *const u8,
        account_id_length: usize,
        state_handle: *mut c_void,
        ke1_out: *mut u8,
        ke1_length: usize,
    ) -> i32;
    fn opaque_agent_generate_ke3(
        agent_handle: *mut c_void,
        ke2: *const u8,
        ke2_length: usize,
        state_handle: *mut c_void,
        ke3_out: *mut u8,
        ke3_length: usize,
    ) -> i32;
}

const PUBLIC_KEY_LENGTH: usize = 32;
const KE1_LENGTH: usize = 1273;
const KE2_LENGTH: usize = 1377;
const KE3_LENGTH: usize = 65;
const UNSUPPORTED_VERSION: i32 = -10;

#[test]
fn ffi_invalid_public_key_returns_error_code() {
    unsafe {
        let zero_key = [0u8; PUBLIC_KEY_LENGTH];
        let mut handle = ptr::null_mut();
        let rc = opaque_agent_create(zero_key.as_ptr(), zero_key.len(), &mut handle);
        assert_ne!(rc, 0);
        assert!(handle.is_null());
    }
}

#[test]
fn ffi_relay_preserves_unsupported_version_error_code() {
    unsafe {
        let mut keypair = ptr::null_mut();
        assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);

        let mut relay = ptr::null_mut();
        assert_eq!(opaque_relay_create(keypair, &mut relay), 0);

        let mut relay_state = ptr::null_mut();
        assert_eq!(opaque_relay_state_create(&mut relay_state), 0);

        let account_id = b"alice@example.com";
        let mut ke1 = vec![0u8; KE1_LENGTH];
        ke1[0] = 0x02;
        let mut ke2 = vec![0u8; KE2_LENGTH];

        let rc = opaque_relay_generate_ke2(
            relay,
            ke1.as_ptr(),
            ke1.len(),
            account_id.as_ptr(),
            account_id.len(),
            ptr::null(),
            0,
            ke2.as_mut_ptr(),
            ke2.len(),
            relay_state,
        );
        assert_eq!(rc, UNSUPPORTED_VERSION);

        opaque_relay_state_destroy(&mut relay_state);
        opaque_relay_destroy(&mut relay);
        opaque_relay_keypair_destroy(&mut keypair);
    }
}

#[test]
fn ffi_agent_preserves_unsupported_version_error_code() {
    const ACCOUNT_ID: &[u8] = b"alice@example.com";
    const PASSWORD: &[u8] = b"correct horse battery staple";

    unsafe {
        let mut keypair = ptr::null_mut();
        assert_eq!(opaque_relay_keypair_generate(&mut keypair), 0);

        let mut relay_public_key = [0u8; PUBLIC_KEY_LENGTH];
        assert_eq!(
            opaque_relay_keypair_get_public_key(
                keypair,
                relay_public_key.as_mut_ptr(),
                relay_public_key.len(),
            ),
            0
        );

        let mut agent = ptr::null_mut();
        assert_eq!(
            opaque_agent_create(
                relay_public_key.as_ptr(),
                relay_public_key.len(),
                &mut agent,
            ),
            0
        );

        let mut agent_state = ptr::null_mut();
        assert_eq!(opaque_agent_state_create(&mut agent_state), 0);

        let mut ke1 = vec![0u8; KE1_LENGTH];
        assert_eq!(
            opaque_agent_generate_ke1(
                agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                agent_state,
                ke1.as_mut_ptr(),
                ke1.len(),
            ),
            0
        );

        let mut ke2 = vec![0u8; KE2_LENGTH];
        ke2[0] = 0x02;
        let mut ke3 = vec![0u8; KE3_LENGTH];

        let rc = opaque_agent_generate_ke3(
            agent,
            ke2.as_ptr(),
            ke2.len(),
            agent_state,
            ke3.as_mut_ptr(),
            ke3.len(),
        );
        assert_eq!(rc, UNSUPPORTED_VERSION);

        opaque_agent_state_destroy(&mut agent_state);
        opaque_agent_destroy(&mut agent);
        opaque_relay_keypair_destroy(&mut keypair);
    }
}
