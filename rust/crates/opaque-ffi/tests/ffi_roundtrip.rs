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
    fn opaque_relay_create_registration_response(
        relay_handle: *const c_void,
        request_data: *const u8,
        request_length: usize,
        account_id: *const u8,
        account_id_length: usize,
        response_data: *mut u8,
        response_buffer_size: usize,
    ) -> i32;
    fn opaque_relay_build_credentials(
        registration_record: *const u8,
        record_length: usize,
        credentials_out: *mut u8,
        credentials_out_length: usize,
    ) -> i32;
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
    fn opaque_relay_finish(
        relay_handle: *const c_void,
        ke3_data: *const u8,
        ke3_length: usize,
        state_handle: *mut c_void,
        session_key: *mut u8,
        session_key_buffer_size: usize,
        master_key_out: *mut u8,
        master_key_buffer_size: usize,
    ) -> i32;

    fn opaque_agent_create(
        relay_public_key: *const u8,
        key_length: usize,
        out_handle: *mut *mut c_void,
    ) -> i32;
    fn opaque_agent_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_state_create(out_handle: *mut *mut c_void) -> i32;
    fn opaque_agent_state_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_create_registration_request(
        agent_handle: *mut c_void,
        password: *const u8,
        password_length: usize,
        state_handle: *mut c_void,
        request_out: *mut u8,
        request_length: usize,
    ) -> i32;
    fn opaque_agent_finalize_registration(
        agent_handle: *mut c_void,
        response: *const u8,
        response_length: usize,
        state_handle: *mut c_void,
        record_out: *mut u8,
        record_length: usize,
    ) -> i32;
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
    fn opaque_agent_finish(
        agent_handle: *mut c_void,
        state_handle: *mut c_void,
        session_key_out: *mut u8,
        session_key_length: usize,
        master_key_out: *mut u8,
        master_key_length: usize,
    ) -> i32;
}

const PUBLIC_KEY_LENGTH: usize = 32;
const REGISTRATION_REQUEST_LENGTH: usize = 33;
const REGISTRATION_RESPONSE_LENGTH: usize = 65;
const REGISTRATION_RECORD_LENGTH: usize = 169;
const KE1_LENGTH: usize = 1273;
const KE2_LENGTH: usize = 1377;
const KE3_LENGTH: usize = 65;
const SESSION_KEY_LENGTH: usize = 64;
const MASTER_KEY_LENGTH: usize = 32;

#[test]
fn ffi_agent_and_relay_roundtrip() {
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

        let mut relay = ptr::null_mut();
        assert_eq!(opaque_relay_create(keypair, &mut relay), 0);

        let mut agent = ptr::null_mut();
        assert_eq!(
            opaque_agent_create(
                relay_public_key.as_ptr(),
                relay_public_key.len(),
                &mut agent,
            ),
            0
        );

        let mut registration_state = ptr::null_mut();
        assert_eq!(opaque_agent_state_create(&mut registration_state), 0);

        let mut registration_request = vec![0u8; REGISTRATION_REQUEST_LENGTH];
        assert_eq!(
            opaque_agent_create_registration_request(
                agent,
                PASSWORD.as_ptr(),
                PASSWORD.len(),
                registration_state,
                registration_request.as_mut_ptr(),
                registration_request.len(),
            ),
            0
        );

        let mut registration_response = vec![0u8; REGISTRATION_RESPONSE_LENGTH];
        assert_eq!(
            opaque_relay_create_registration_response(
                relay,
                registration_request.as_ptr(),
                registration_request.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                registration_response.as_mut_ptr(),
                registration_response.len(),
            ),
            0
        );

        let mut registration_record = vec![0u8; REGISTRATION_RECORD_LENGTH];
        assert_eq!(
            opaque_agent_finalize_registration(
                agent,
                registration_response.as_ptr(),
                registration_response.len(),
                registration_state,
                registration_record.as_mut_ptr(),
                registration_record.len(),
            ),
            0
        );

        let mut credentials = vec![0u8; REGISTRATION_RECORD_LENGTH];
        assert_eq!(
            opaque_relay_build_credentials(
                registration_record.as_ptr(),
                registration_record.len(),
                credentials.as_mut_ptr(),
                credentials.len(),
            ),
            0
        );

        opaque_agent_state_destroy(&mut registration_state);
        assert!(registration_state.is_null());

        let mut agent_state = ptr::null_mut();
        let mut relay_state = ptr::null_mut();
        assert_eq!(opaque_agent_state_create(&mut agent_state), 0);
        assert_eq!(opaque_relay_state_create(&mut relay_state), 0);

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
        assert_eq!(
            opaque_relay_generate_ke2(
                relay,
                ke1.as_ptr(),
                ke1.len(),
                ACCOUNT_ID.as_ptr(),
                ACCOUNT_ID.len(),
                credentials.as_ptr(),
                credentials.len(),
                ke2.as_mut_ptr(),
                ke2.len(),
                relay_state,
            ),
            0
        );

        let mut ke3 = vec![0u8; KE3_LENGTH];
        assert_eq!(
            opaque_agent_generate_ke3(
                agent,
                ke2.as_ptr(),
                ke2.len(),
                agent_state,
                ke3.as_mut_ptr(),
                ke3.len(),
            ),
            0
        );

        let mut relay_session_key = [0u8; SESSION_KEY_LENGTH];
        let mut relay_master_key = [0u8; MASTER_KEY_LENGTH];
        assert_eq!(
            opaque_relay_finish(
                relay,
                ke3.as_ptr(),
                ke3.len(),
                relay_state,
                relay_session_key.as_mut_ptr(),
                relay_session_key.len(),
                relay_master_key.as_mut_ptr(),
                relay_master_key.len(),
            ),
            0
        );

        let mut agent_session_key = [0u8; SESSION_KEY_LENGTH];
        let mut agent_master_key = [0u8; MASTER_KEY_LENGTH];
        assert_eq!(
            opaque_agent_finish(
                agent,
                agent_state,
                agent_session_key.as_mut_ptr(),
                agent_session_key.len(),
                agent_master_key.as_mut_ptr(),
                agent_master_key.len(),
            ),
            0
        );

        assert_eq!(agent_session_key, relay_session_key);
        assert_eq!(agent_master_key, relay_master_key);

        opaque_agent_state_destroy(&mut agent_state);
        opaque_relay_state_destroy(&mut relay_state);
        opaque_agent_destroy(&mut agent);
        opaque_relay_destroy(&mut relay);
        opaque_relay_keypair_destroy(&mut keypair);

        assert!(agent_state.is_null());
        assert!(relay_state.is_null());
        assert!(agent.is_null());
        assert!(relay.is_null());
        assert!(keypair.is_null());
    }
}

#[test]
fn ffi_agent_invalid_public_key_reports_error() {
    unsafe {
        let zero_key = [0u8; PUBLIC_KEY_LENGTH];
        let mut handle = ptr::null_mut();

        let rc = opaque_agent_create(zero_key.as_ptr(), zero_key.len(), &mut handle);
        assert_ne!(rc, 0);
        assert!(handle.is_null());
    }
}
