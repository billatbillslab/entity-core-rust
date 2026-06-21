//! C FFI bindings for Entity Core Protocol.
//!
//! Provides a C-compatible shared library (.so/.dylib/.dll) exposing
//! Entity Core primitives: ECF encoding, hashing, crypto, entities,
//! wire codec, and peer lifecycle.
//!
//! Every `extern "C"` function is panic-safe via `catch_unwind`.

/// Panic-safe wrapper for FFI function bodies.
///
/// Catches any panic and returns a sentinel value after setting
/// the thread-local error message.
///
/// Use `ffi_fn!(expr)` for types with meaningful zero/null defaults (Handle, EntityCoreBuffer).
/// Use `ffi_fn!(expr, sentinel)` for types needing explicit panic return values.
macro_rules! ffi_fn {
    ($body:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => {
                $crate::error::set_last_error("internal panic");
                Default::default()
            }
        }
    };
    ($body:expr, $panic_val:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(result) => result,
            Err(_) => {
                $crate::error::set_last_error("internal panic");
                $panic_val
            }
        }
    };
}

pub mod types;
pub mod error;
pub mod handles;
pub mod ecf;
pub mod hash;
pub mod crypto;
pub mod entity;
pub mod wire;
pub mod peer;
