//! Tier 3: Entity lifecycle — new, free, accessors, validate.

use crate::error::set_last_error;
use crate::handles::HandleMap;
use crate::types::{EntityCoreBuffer, EntityCoreError, Handle};

use std::sync::LazyLock;

pub(crate) static ENTITIES: LazyLock<HandleMap<entity_entity::Entity>> =
    LazyLock::new(HandleMap::new);

/// Create a new entity from type string and CBOR data bytes.
///
/// Computes the content hash. Returns 0 on error.
///
/// # Safety
/// `type_ptr`/`type_len` must be valid UTF-8, `data_ptr`/`data_len` must be valid bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_new(
    type_ptr: *const u8,
    type_len: usize,
    data_ptr: *const u8,
    data_len: usize,
) -> Handle {
    ffi_fn!({
        let entity_type = match unsafe {
            std::str::from_utf8(std::slice::from_raw_parts(type_ptr, type_len))
        } {
            Ok(s) => s,
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 type: {}", e));
                return 0;
            }
        };
        let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) }.to_vec();
        match entity_entity::Entity::new(entity_type, data) {
            Ok(e) => ENTITIES.insert(e),
            Err(e) => {
                set_last_error(&format!("entity creation failed: {}", e));
                0
            }
        }
    })
}

/// Free an entity handle.
#[no_mangle]
pub extern "C" fn entity_free(handle: Handle) {
    let _ = ENTITIES.remove(handle);
}

/// Get the entity type string as a buffer.
#[no_mangle]
pub extern "C" fn entity_get_type(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match ENTITIES.with(handle, |e| e.entity_type.clone()) {
            Some(t) => EntityCoreBuffer::from_vec(t.into_bytes()),
            None => {
                set_last_error("invalid entity handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Get the entity data bytes as a buffer.
#[no_mangle]
pub extern "C" fn entity_get_data(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match ENTITIES.with(handle, |e| e.data.clone()) {
            Some(d) => EntityCoreBuffer::from_vec(d),
            None => {
                set_last_error("invalid entity handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Get the entity content hash as 33 bytes.
#[no_mangle]
pub extern "C" fn entity_get_hash(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match ENTITIES.with(handle, |e| e.content_hash.to_bytes()) {
            Some(h) => EntityCoreBuffer::from_vec(h.to_vec()),
            None => {
                set_last_error("invalid entity handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Validate an entity's content hash.
#[no_mangle]
pub extern "C" fn entity_validate(handle: Handle) -> EntityCoreError {
    ffi_fn!({
        match ENTITIES.with(handle, |e| e.validate()) {
            Some(Ok(())) => EntityCoreError::Ok,
            Some(Err(e)) => {
                set_last_error(&format!("validation failed: {}", e));
                EntityCoreError::InvalidArgument
            }
            None => {
                set_last_error("invalid entity handle");
                EntityCoreError::InvalidArgument
            }
        }
    }, EntityCoreError::InternalError)
}
