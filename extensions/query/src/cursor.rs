//! Cursor encoding/decoding for pagination.
//!
//! Cursors are opaque, base64-encoded strings that encode the position
//! in a sorted result set (the last path seen).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use entity_handler::HandlerError;

/// Encode a cursor from the last result's path.
pub fn encode_cursor(last_path: &str) -> String {
    URL_SAFE_NO_PAD.encode(last_path.as_bytes())
}

/// Decode a cursor to recover the last path.
pub fn decode_cursor(cursor: &str) -> Result<String, HandlerError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| HandlerError::InvalidParams("invalid cursor encoding".into()))?;
    String::from_utf8(bytes)
        .map_err(|_| HandlerError::InvalidParams("invalid cursor content".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_roundtrip() {
        let path = "app/users/alice";
        let cursor = encode_cursor(path);
        let decoded = decode_cursor(&cursor).unwrap();
        assert_eq!(decoded, path);
    }

    #[test]
    fn test_cursor_invalid() {
        assert!(decode_cursor("!!!invalid!!!").is_err());
    }
}
