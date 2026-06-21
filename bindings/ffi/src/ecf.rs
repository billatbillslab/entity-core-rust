//! Tier 0: ECF (deterministic CBOR) value builders, encode/decode, diagnostic.

use crate::error::set_last_error;
use crate::handles::HandleMap;
use crate::types::{EntityCoreBuffer, EntityCoreError, Handle};

use std::sync::LazyLock;

static ECF_VALUES: LazyLock<HandleMap<entity_ecf::Value>> = LazyLock::new(HandleMap::new);

// ---------------------------------------------------------------------------
// Value builders
// ---------------------------------------------------------------------------

/// Create a CBOR text string value.
///
/// # Safety
/// `ptr` must point to `len` valid UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn ecf_value_text(ptr: *const u8, len: usize) -> Handle {
    ffi_fn!({
        let s = unsafe { std::str::from_utf8(std::slice::from_raw_parts(ptr, len)) };
        match s {
            Ok(s) => ECF_VALUES.insert(entity_ecf::text(s)),
            Err(e) => {
                set_last_error(&format!("invalid UTF-8: {}", e));
                0
            }
        }
    })
}

/// Create a CBOR byte string value.
///
/// # Safety
/// `ptr` must point to `len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn ecf_value_bytes(ptr: *const u8, len: usize) -> Handle {
    ffi_fn!({
        let data = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        ECF_VALUES.insert(entity_ecf::bytes(data))
    })
}

/// Create a CBOR integer value.
#[no_mangle]
pub extern "C" fn ecf_value_integer(val: i64) -> Handle {
    ffi_fn!({
        ECF_VALUES.insert(entity_ecf::integer(val))
    })
}

/// Create a CBOR boolean value.
#[no_mangle]
pub extern "C" fn ecf_value_bool(val: bool) -> Handle {
    ffi_fn!({
        ECF_VALUES.insert(entity_ecf::bool_val(val))
    })
}

/// Create a CBOR null value.
#[no_mangle]
pub extern "C" fn ecf_value_null() -> Handle {
    ffi_fn!({
        ECF_VALUES.insert(entity_ecf::null())
    })
}

/// Create a CBOR float value.
#[no_mangle]
pub extern "C" fn ecf_value_float(val: f64) -> Handle {
    ffi_fn!({
        ECF_VALUES.insert(entity_ecf::Value::Float(val))
    })
}

/// Create a CBOR array from an array of value handles.
///
/// # Safety
/// `handles` must point to `count` valid `Handle` values.
#[no_mangle]
pub unsafe extern "C" fn ecf_value_array(handles: *const Handle, count: usize) -> Handle {
    ffi_fn!({
        let handles = unsafe { std::slice::from_raw_parts(handles, count) };
        let mut items = Vec::with_capacity(count);
        for &h in handles {
            match ECF_VALUES.remove(h) {
                Some(v) => items.push(v),
                None => {
                    set_last_error("invalid value handle in array");
                    return 0;
                }
            }
        }
        ECF_VALUES.insert(entity_ecf::Value::Array(items))
    })
}

/// Create an empty CBOR map value.
#[no_mangle]
pub extern "C" fn ecf_value_map_new() -> Handle {
    ffi_fn!({
        ECF_VALUES.insert(entity_ecf::Value::Map(vec![]))
    })
}

/// Insert a key-value pair into a map. Consumes the key and value handles.
#[no_mangle]
pub extern "C" fn ecf_value_map_insert(
    map_handle: Handle,
    key_handle: Handle,
    value_handle: Handle,
) -> EntityCoreError {
    ffi_fn!({
        let key = match ECF_VALUES.remove(key_handle) {
            Some(v) => v,
            None => {
                set_last_error("invalid key handle");
                return EntityCoreError::InvalidArgument;
            }
        };
        let value = match ECF_VALUES.remove(value_handle) {
            Some(v) => v,
            None => {
                set_last_error("invalid value handle");
                return EntityCoreError::InvalidArgument;
            }
        };
        match ECF_VALUES.with_mut(map_handle, |map| {
            if let entity_ecf::Value::Map(ref mut entries) = map {
                entries.push((key.clone(), value.clone()));
                true
            } else {
                false
            }
        }) {
            Some(true) => EntityCoreError::Ok,
            Some(false) => {
                set_last_error("handle is not a map");
                EntityCoreError::InvalidArgument
            }
            None => {
                set_last_error("invalid map handle");
                EntityCoreError::InvalidArgument
            }
        }
    }, EntityCoreError::InternalError)
}

/// Free a value handle.
#[no_mangle]
pub extern "C" fn ecf_value_free(handle: Handle) {
    let _ = ECF_VALUES.remove(handle);
}

// ---------------------------------------------------------------------------
// Encode / Decode
// ---------------------------------------------------------------------------

/// Encode a value to ECF (deterministic CBOR) bytes. Consumes the handle.
#[no_mangle]
pub extern "C" fn ecf_encode(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match ECF_VALUES.remove(handle) {
            Some(v) => EntityCoreBuffer::from_vec(entity_ecf::to_ecf(&v)),
            None => {
                set_last_error("invalid value handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Decode ECF/CBOR bytes into a value handle.
///
/// # Safety
/// `ptr` must point to `len` valid bytes of CBOR data.
#[no_mangle]
pub unsafe extern "C" fn ecf_decode(ptr: *const u8, len: usize) -> Handle {
    ffi_fn!({
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        match ciborium::from_reader::<entity_ecf::Value, _>(data) {
            Ok(v) => ECF_VALUES.insert(v),
            Err(e) => {
                set_last_error(&format!("CBOR decode error: {}", e));
                0
            }
        }
    })
}

/// Encode CBOR bytes to diagnostic notation string.
///
/// # Safety
/// `ptr` must point to `len` valid bytes of CBOR data.
#[no_mangle]
pub unsafe extern "C" fn ecf_to_diag(ptr: *const u8, len: usize) -> EntityCoreBuffer {
    ffi_fn!({
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        match cbor_diag::parse_bytes(data) {
            Ok(item) => EntityCoreBuffer::from_vec(item.to_diag_pretty().into_bytes()),
            Err(e) => {
                set_last_error(&format!("diagnostic error: {}", e));
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Parse CBOR diagnostic notation to bytes.
///
/// # Safety
/// `ptr` must point to `len` valid UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn ecf_from_diag(ptr: *const u8, len: usize) -> EntityCoreBuffer {
    ffi_fn!({
        let s = match unsafe { std::str::from_utf8(std::slice::from_raw_parts(ptr, len)) } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8: {}", e));
                return EntityCoreBuffer::null();
            }
        };
        match cbor_diag::parse_diag(s) {
            Ok(item) => EntityCoreBuffer::from_vec(item.to_bytes()),
            Err(e) => {
                set_last_error(&format!("diagnostic parse error: {}", e));
                EntityCoreBuffer::null()
            }
        }
    })
}
