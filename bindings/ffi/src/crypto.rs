//! Tier 2: Ed25519 keypair, sign, verify, PeerID.

use crate::error::set_last_error;
use crate::handles::HandleMap;
use crate::types::{EntityCoreBuffer, EntityCoreError, Handle};

use std::sync::LazyLock;

static KEYPAIRS: LazyLock<HandleMap<entity_crypto::Keypair>> = LazyLock::new(HandleMap::new);

/// Generate a new random Ed25519 keypair.
#[no_mangle]
pub extern "C" fn entity_keypair_generate() -> Handle {
    ffi_fn!({
        KEYPAIRS.insert(entity_crypto::Keypair::generate())
    })
}

/// Create an Ed25519 keypair from a 32-byte seed (deterministic).
///
/// # Safety
/// `seed_ptr` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn entity_keypair_from_seed(seed_ptr: *const u8) -> Handle {
    ffi_fn!({
        let seed = unsafe { std::slice::from_raw_parts(seed_ptr, 32) };
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed);
        KEYPAIRS.insert(entity_crypto::Keypair::from_seed(seed_arr))
    })
}

/// Free a keypair handle.
#[no_mangle]
pub extern "C" fn entity_keypair_free(handle: Handle) {
    let _ = KEYPAIRS.remove(handle);
}

/// Get the 32-byte public key from a keypair.
#[no_mangle]
pub extern "C" fn entity_keypair_public_key(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match KEYPAIRS.with(handle, |kp| kp.public_key_bytes()) {
            Some(pk) => EntityCoreBuffer::from_vec(pk.to_vec()),
            None => {
                set_last_error("invalid keypair handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Get the PeerID string for a keypair.
#[no_mangle]
pub extern "C" fn entity_keypair_peer_id(handle: Handle) -> EntityCoreBuffer {
    ffi_fn!({
        match KEYPAIRS.with(handle, |kp| kp.peer_id().to_string()) {
            Some(pid) => EntityCoreBuffer::from_vec(pid.into_bytes()),
            None => {
                set_last_error("invalid keypair handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Sign a message with a keypair. Returns 64-byte Ed25519 signature.
///
/// # Safety
/// `msg_ptr`/`msg_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn entity_sign(
    handle: Handle,
    msg_ptr: *const u8,
    msg_len: usize,
) -> EntityCoreBuffer {
    ffi_fn!({
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        match KEYPAIRS.with(handle, |kp| kp.sign(msg)) {
            Some(sig) => EntityCoreBuffer::from_vec(sig.to_vec()),
            None => {
                set_last_error("invalid keypair handle");
                EntityCoreBuffer::null()
            }
        }
    })
}

/// Verify an Ed25519 signature.
///
/// # Safety
/// `pubkey_ptr` must point to 32 bytes, `sig_ptr` to 64 bytes,
/// `msg_ptr`/`msg_len` must be valid.
#[no_mangle]
pub unsafe extern "C" fn entity_verify(
    pubkey_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> EntityCoreError {
    ffi_fn!({
        let pubkey_slice = unsafe { std::slice::from_raw_parts(pubkey_ptr, 32) };
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(pubkey_slice);
        let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
        let sig = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) };
        match entity_crypto::Keypair::verify(&pubkey, msg, sig) {
            Ok(()) => EntityCoreError::Ok,
            Err(e) => {
                set_last_error(&format!("verify failed: {}", e));
                EntityCoreError::CryptoError
            }
        }
    }, EntityCoreError::InternalError)
}
