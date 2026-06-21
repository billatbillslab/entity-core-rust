//! Tier 3: Wire codec — entity encode/decode to CBOR wire format.

use crate::entity::ENTITIES;
use crate::error::set_last_error;
use crate::types::{EntityCoreBuffer, Handle};

/// Encode an entity to wire format (CBOR bytes: {type, data, content_hash}).
/// Does NOT consume the entity handle.
#[no_mangle]
pub extern "C" fn entity_encode(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match ENTITIES.with(handle, |e| entity_wire::encode_entity(e)) {
            Some(bytes) => EntityCoreBuffer::from_vec(bytes),
            None => {
                set_last_error("invalid entity handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Decode wire-format CBOR bytes into an entity handle.
///
/// # Safety
/// `ptr`/`len` must point to valid CBOR bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_decode(ptr: *const u8, len: usize) -> Handle {
    ffi_fn!({
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        match entity_wire::decode_entity(data) {
            Ok(e) => ENTITIES.insert(e),
            Err(e) => {
                set_last_error(&format!("decode error: {}", e));
                0
            }
        }
    })
}
