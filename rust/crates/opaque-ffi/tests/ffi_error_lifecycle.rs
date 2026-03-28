use std::ffi::c_void;
use std::ptr;

use opaque_ffi as _;

unsafe extern "C" {
    fn opaque_agent_create(
        relay_public_key: *const u8,
        key_length: usize,
        out_handle: *mut *mut c_void,
    ) -> i32;
}

#[test]
fn ffi_invalid_public_key_returns_error_code() {
    unsafe {
        let zero_key = [0u8; 32];
        let mut handle = ptr::null_mut();
        let rc = opaque_agent_create(zero_key.as_ptr(), zero_key.len(), &mut handle);
        assert_ne!(rc, 0);
        assert!(handle.is_null());
    }
}
