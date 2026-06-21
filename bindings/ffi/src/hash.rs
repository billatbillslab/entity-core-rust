//! Tier 1: Content hash compute/validate/format.

use crate::error::set_last_error;
use crate::types::{EntityCoreBuffer, EntityCoreError};

/// Compute the content hash of an entity (type + data).
///
/// Returns 33 bytes (algorithm byte + 32-byte SHA-256 digest).
///
/// # Safety
/// `type_ptr`/`type_len` and `data_ptr`/`data_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_compute(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let entity_type = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(type_ptr, type_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 type: {}", e));
                return EntityCoreBuffer::null();
            }
        };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let hash = entity_hash::Hash::compute(entity_type, data);
        EntityCoreBuffer::from_vec(hash.to_bytes().to_vec())
    })
}

/// Validate that a hash matches the given type + data.
///
/// # Safety
/// All pointer/length pairs must be valid. `hash_ptr` must point to 33 bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_validate(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
    hash_ptr: *const u8,
) -> EntityCoreError {
    ffi_fn!({
        let entity_type = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(type_ptr, type_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 type: {}", e));
                return EntityCoreError::InvalidArgument;
            }
        };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
        let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, 33) };
        let claimed = match entity_hash::Hash::from_bytes(hash_bytes) {
            Ok(h) => h,
            Err(e) => {
                set_last_error(&format!("invalid hash: {}", e));
                return EntityCoreError::InvalidArgument;
            }
        };
        match entity_hash::Hash::validate(entity_type, data, &claimed) {
            Ok(()) => EntityCoreError::Ok,
            Err(e) => {
                set_last_error(&format!("hash mismatch: {}", e));
                EntityCoreError::InvalidArgument
            }
        }
    }, EntityCoreError::InternalError)
}

/// Format a 33-byte hash as hex string.
///
/// # Safety
/// `hash_ptr` must point to 33 valid bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_to_hex(hash_ptr: *const u8) -> EntityCoreBuffer {
    ffi_fn!({
        let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, 33) };
        let hex: String = hash_bytes.iter().map(|b| format!("{:02x}", b)).collect();
        EntityCoreBuffer::from_vec(hex.into_bytes())
    })
}

/// Parse a hex string back to 33-byte hash.
///
/// # Safety
/// `hex_ptr`/`hex_len` must point to a valid hex string (66 chars).
#[no_mangle]
pub unsafe extern "C" fn entity_hash_from_hex(
    hex_ptr: *const u8,
    hex_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let hex = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(hex_ptr, hex_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8: {}", e));
                return EntityCoreBuffer::null();
            }
        };
        if hex.len() != 66 {
            set_last_error("hex string must be 66 characters (33 bytes)");
            return EntityCoreBuffer::null();
        }
        let mut bytes = vec![0u8; 33];
        for i in 0..33 {
            match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
                Ok(b) => bytes[i] = b,
                Err(e) => {
                    set_last_error(&format!("invalid hex: {}", e));
                    return EntityCoreBuffer::null();
                }
            }
        }
        EntityCoreBuffer::from_vec(bytes)
    })
}

/// Format a 33-byte hash as the display string ("ecfv1-sha256:...").
///
/// # Safety
/// `hash_ptr` must point to 33 valid bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_hash_to_display(hash_ptr: *const u8) -> EntityCoreBuffer {
    ffi_fn!({
        let hash_bytes = unsafe { std::slice::from_raw_parts(hash_ptr, 33) };
        match entity_hash::Hash::from_bytes(hash_bytes) {
            Ok(h) => EntityCoreBuffer::from_vec(h.to_string().into_bytes()),
            Err(e) => {
                set_last_error(&format!("invalid hash: {}", e));
                EntityCoreBuffer::null()
            }
        }
    })
}
