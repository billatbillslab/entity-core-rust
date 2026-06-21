//! Thread-local error handling for FFI.

use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Set the last error message for the current thread.
pub fn set_last_error(msg: &str) {
    let c = CString::new(msg).unwrap_or_else(|_| CString::new("(error contained null)").unwrap());
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(c);
    });
}

/// Get a pointer to the last error message for the current thread.
///
/// Returns null if no error has been set. The pointer is valid until the
/// next FFI call on the same thread.
#[no_mangle]
pub extern "C" fn entity_core_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        e.borrow()
            .as_ref()
            .map(|c| c.as_ptr())
            .unwrap_or(std::ptr::null())
    })
}
