//! Shared C-compatible types for the Entity Core FFI.

/// Opaque handle type for FFI objects.
pub type Handle = u64;

/// A buffer of bytes owned by the FFI layer.
///
/// Callers must free with `entity_core_buffer_free`.
#[repr(C)]
pub struct EntityCoreBuffer {
    pub data: *mut u8,
    pub len: usize,
}

impl Default for EntityCoreBuffer {
    fn default() -> Self {
        Self::null()
    }
}

impl EntityCoreBuffer {
    /// Create a buffer from a Rust Vec, transferring ownership to the C side.
    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut v = v.into_boxed_slice();
        let data = v.as_mut_ptr();
        let len = v.len();
        std::mem::forget(v);
        Self { data, len }
    }

    /// Create a null/empty buffer.
    pub fn null() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Convert back to a Rust slice (unsafe — caller must guarantee validity).
    ///
    /// # Safety
    /// The buffer must have been created by `from_vec` and not yet freed.
    pub unsafe fn as_slice(&self) -> &[u8] {
        if self.data.is_null() || self.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.len) }
        }
    }
}

/// Error codes returned by FFI functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityCoreError {
    Ok = 0,
    InvalidArgument = 1,
    NotFound = 2,
    PermissionDenied = 3,
    StorageError = 4,
    NetworkError = 5,
    EncodingError = 6,
    CryptoError = 7,
    InternalError = 99,
}

/// Free a buffer previously returned by the FFI.
///
/// # Safety
/// Must only be called once on a buffer returned by this library.
#[no_mangle]
pub unsafe extern "C" fn entity_core_buffer_free(buf: EntityCoreBuffer) {
    if !buf.data.is_null() && buf.len > 0 {
        let _ = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(buf.data, buf.len)) };
    }
}
