#![no_main]

use std::ffi::c_void;
use std::ptr;

use libfuzzer_sys::fuzz_target;
use opaque_ffi as _;

unsafe extern "C" {
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
}

fuzz_target!(|data: &[u8]| {
    let (relay_pk, rest) = data.split_at(data.len().min(32));
    let password = rest;

    let mut agent = ptr::dangling_mut::<c_void>();

    unsafe {
        let create_rc = opaque_agent_create(relay_pk.as_ptr(), relay_pk.len(), &mut agent);

        if create_rc == 0 {
            assert!(!agent.is_null());
            let mut state = ptr::null_mut();
            let state_rc = opaque_agent_state_create(&mut state);

            if state_rc == 0 {
                assert!(!state.is_null());
                let mut request_out = [0xA5u8; 33];
                let request_len = if password.len() % 2 == 0 {
                    request_out.len()
                } else {
                    password.len().min(request_out.len())
                };
                let request_rc = opaque_agent_create_registration_request(
                    agent,
                    password.as_ptr(),
                    password.len(),
                    state,
                    request_out.as_mut_ptr(),
                    request_len,
                );
                if request_rc == 0 {
                    assert!(request_out.iter().any(|byte| *byte != 0xA5));
                } else {
                    assert!(request_out.iter().all(|byte| *byte == 0xA5));
                }
                opaque_agent_state_destroy(&mut state);
                assert!(state.is_null());
            } else {
                assert!(state.is_null());
            }

            opaque_agent_destroy(&mut agent);
            assert!(agent.is_null());
        } else {
            assert!(agent.is_null());
        }
    }
});
