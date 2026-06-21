//! Entity, Envelope, and URI types.
//!
//! An Entity is the fundamental unit of data: `{type, data}` with a content hash.
//! An Envelope wraps an entity with included entities (signatures, identities, capabilities).

use std::collections::BTreeMap;

use entity_hash::Hash;
use thiserror::Error;

/// System type for signature entities.
pub const TYPE_SIGNATURE: &str = "system/signature";

/// `system/deletion-marker` — ENTITY-NATIVE-TYPE-SYSTEM v4.2.0 §4.9.
/// Zero-field canonical entity. Its `data` is the CBOR empty map (`0xa0`).
pub const TYPE_DELETION_MARKER: &str = "system/deletion-marker";

/// The canonical hash of `system/deletion-marker`, hex-encoded:
/// `ecf-sha256:689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6`.
/// Implementations MUST verify their local computation matches this value
/// (NATIVE-TYPE-SYSTEM §4.9) — any deviation signals an ECF-encoding bug.
pub const CANONICAL_DELETION_MARKER_HASH_HEX: &str =
    "689ae4679f69f006e4bf7cb7c7a9155d0de5fb9fe31e81692dca5769eda9e0a6";

/// Build the canonical `system/deletion-marker` entity.
/// `data` is the CBOR empty map (`0xa0`).
pub fn canonical_deletion_marker_entity() -> Entity {
    // CBOR empty map = 0xa0 (one byte).
    Entity::new(TYPE_DELETION_MARKER, vec![0xa0u8])
        .expect("canonical deletion marker must construct")
}

/// Return the canonical `system/deletion-marker` content hash. Memoized
/// per-process via OnceLock. The hash MUST equal
/// `CANONICAL_DELETION_MARKER_HASH_HEX` — verified by debug_assert.
pub fn canonical_deletion_marker_hash() -> Hash {
    static CACHED: std::sync::OnceLock<Hash> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| canonical_deletion_marker_entity().content_hash)
}

/// URI scheme for entity references.
pub const URI_SCHEME: &str = "entity://";

/// An entity: the fundamental unit of content-addressed data.
///
/// Contains a type string, raw CBOR data bytes, and its content hash.
/// The data bytes are preserved exactly as received — never decoded and re-encoded.
#[derive(Debug, Clone)]
pub struct Entity {
    /// Entity type string (e.g., "system/handler").
    pub entity_type: String,
    /// Raw CBOR-encoded data bytes (preserved for hash fidelity).
    pub data: Vec<u8>,
    /// Content hash: SHA-256 over ECF-encoded `{data, type}`.
    pub content_hash: Hash,
}

impl Entity {
    /// Create a new entity, computing its content hash under the process
    /// **home** `content_hash_format` ([`entity_hash::default_hash_format`]).
    ///
    /// This is the home-authoring default, correct for non-connection-bound
    /// authoring (peer-startup local state, stored content, substrate,
    /// handler results). It is the SHA-256 floor unless the peer set a
    /// different home format at build (V7 §1.2 / v7.70). Connection-bound
    /// authoring that must honor a negotiated active format (V7 §4.5a) uses
    /// [`Entity::new_with_format`] with the connection's active format.
    ///
    /// Validates that type and data are non-empty.
    pub fn new(entity_type: &str, data: Vec<u8>) -> Result<Self, EntityError> {
        Self::new_with_format(entity_type, data, entity_hash::default_hash_format())
    }

    /// Create a new entity, computing its content hash under an explicit
    /// `content_hash_format` code (V7 §4.5a — author under the connection's
    /// negotiated active format). An unsupported format code is rejected.
    pub fn new_with_format(
        entity_type: &str,
        data: Vec<u8>,
        format_code: u8,
    ) -> Result<Self, EntityError> {
        if entity_type.is_empty() {
            return Err(EntityError::InvalidType("entity type cannot be empty".into()));
        }
        if data.is_empty() {
            return Err(EntityError::MissingField("data".into()));
        }
        let content_hash = Hash::compute_format(entity_type, &data, format_code)
            .map_err(|e| EntityError::InvalidType(e.to_string()))?;
        Ok(Self {
            entity_type: entity_type.to_string(),
            data,
            content_hash,
        })
    }

    /// Validate that the content hash matches the entity's type and data,
    /// recomputing under the entity's own `content_hash_format` (V7 §1.8).
    pub fn validate(&self) -> Result<(), EntityError> {
        Hash::validate(&self.entity_type, &self.data, &self.content_hash).map_err(|e| match e {
            entity_hash::HashError::HashMismatch { expected, actual } => {
                EntityError::HashMismatch { expected, actual }
            }
            other => EntityError::InvalidType(other.to_string()),
        })
    }
}

impl PartialEq for Entity {
    fn eq(&self, other: &Self) -> bool {
        self.content_hash == other.content_hash
    }
}

impl Eq for Entity {}

/// An envelope wraps a root entity with included entities.
///
/// Auth metadata (signatures, identities, capabilities) are separate entities
/// in the `included` map, found by scanning for matching types.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// The primary entity in this envelope.
    pub root: Entity,
    /// Additional entities keyed by content hash (signatures, identities, etc.).
    pub included: BTreeMap<Hash, Entity>,
}

impl Envelope {
    /// Create an envelope with just a root entity.
    pub fn new(root: Entity) -> Self {
        Self {
            root,
            included: BTreeMap::new(),
        }
    }

    /// Create an envelope with a root entity and included entities.
    pub fn with_included(root: Entity, included: BTreeMap<Hash, Entity>) -> Self {
        Self { root, included }
    }

    /// Add an entity to the included map, keyed by its content hash.
    pub fn include(&mut self, entity: Entity) {
        self.included.insert(entity.content_hash, entity);
    }

    /// Find an included entity by its content hash.
    pub fn find_included(&self, hash: &Hash) -> Option<&Entity> {
        self.included.get(hash)
    }

    /// Find a signature entity targeting the given hash.
    ///
    /// Scans included entities for `system/signature` type where the data
    /// contains a `target` field matching the given hash. Returns the first match.
    pub fn find_signature_for(&self, target: &Hash) -> Option<&Entity> {
        find_signature_for_target(self.included.values(), target)
    }

    /// Validate the root entity and all included entities.
    pub fn validate_all(&self) -> Result<(), EntityError> {
        self.root.validate()?;
        for entity in self.included.values() {
            entity.validate()?;
        }
        Ok(())
    }
}

/// Find a signature entity targeting the given hash in an entity collection.
///
/// Scans for `system/signature` entities whose data contains a `target` field
/// matching the given hash. Returns the first match.
///
/// Generic over the input iterator so both `BTreeMap`-backed (Envelope) and
/// `HashMap`-backed (HandlerContext) callers can pass `.values()` directly.
pub fn find_signature_for_target<'a, I>(entities: I, target: &Hash) -> Option<&'a Entity>
where
    I: IntoIterator<Item = &'a Entity>,
{
    for entity in entities {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Some((sig_target, _)) = decode_sig_target_signer(&entity.data) {
                if sig_target == *target {
                    return Some(entity);
                }
            }
        }
    }
    None
}

/// Find a signature entity matching both target hash AND signer identity hash
/// (PROPOSAL-MULTISIG-CORE-PRIMITIVE §4.0 / new helper).
///
/// `find_signature_for_target` returns the *first* signature for a target.
/// Multi-sig verification needs to locate signatures by *both* fields since
/// multiple constituents sign the same target. Used by M4 (per-link sig
/// verification multi-sig branch), M6 (root-trust check), and M7
/// (`check_creator_authority` strict-with-signature).
///
/// Generic over the input iterator so both BTreeMap- and HashMap-backed
/// callers can pass `.values()` directly.
pub fn find_signature_by_signer<'a, I>(
    entities: I,
    target: &Hash,
    signer: &Hash,
) -> Option<&'a Entity>
where
    I: IntoIterator<Item = &'a Entity>,
{
    for entity in entities {
        if entity.entity_type == TYPE_SIGNATURE {
            if let Some((t, s)) = decode_sig_target_signer(&entity.data) {
                if t == *target && s == *signer {
                    return Some(entity);
                }
            }
        }
    }
    None
}

/// Decode just the (target, signer) hashes from a `system/signature` entity's
/// CBOR data. Returns None on any decode failure (defensive — fail-closed
/// callers get a no-match).
fn decode_sig_target_signer(data: &[u8]) -> Option<(Hash, Hash)> {
    let value: ciborium::Value = ciborium::from_reader(data).ok()?;
    let entries = value.as_map()?;
    let mut target = None;
    let mut signer = None;
    for (k, v) in entries {
        match k.as_text() {
            Some("target") => {
                target = v.as_bytes().and_then(|b| Hash::from_bytes(b).ok());
            }
            Some("signer") => {
                signer = v.as_bytes().and_then(|b| Hash::from_bytes(b).ok());
            }
            _ => {}
        }
    }
    Some((target?, signer?))
}

/// A parsed entity URI: `entity://<peer_id>/<path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityUri {
    /// Peer identifier (PeerID or empty for local).
    pub peer_id: String,
    /// Path (e.g., "system/tree"). No leading slash.
    pub path: String,
}

impl EntityUri {
    /// Parse an entity URI string.
    ///
    /// Format: `entity://<peer_id>/<path>` or `entity://<peer_id>`.
    pub fn parse(s: &str) -> Result<Self, EntityError> {
        let rest = s.strip_prefix(URI_SCHEME).ok_or_else(|| {
            EntityError::InvalidUri(format!("expected '{}' prefix", URI_SCHEME))
        })?;
        match rest.find('/') {
            Some(idx) => Ok(Self {
                peer_id: rest[..idx].to_string(),
                path: rest[idx + 1..].to_string(),
            }),
            None => Ok(Self {
                peer_id: rest.to_string(),
                path: String::new(),
            }),
        }
    }

    /// Normalize a path or URI to just the path portion.
    ///
    /// Strips `entity://` prefix and peer_id if present.
    pub fn normalize_path(uri: &str) -> &str {
        match uri.strip_prefix(URI_SCHEME) {
            Some(rest) => match rest.find('/') {
                Some(idx) => &rest[idx + 1..],
                None => "",
            },
            None => uri,
        }
    }

    /// Extract the handler path from a URI or path.
    ///
    /// For fully-qualified URIs, strips scheme + peer_id.
    /// For bare paths, returns as-is.
    pub fn extract_handler_path(uri: &str) -> &str {
        Self::normalize_path(uri)
    }

    /// Check if a string segment looks like a Base58 PeerID (46 chars).
    pub fn is_peer_id(segment: &str) -> bool {
        const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        segment.len() == 46 && segment.bytes().all(|b| BASE58.contains(&b))
    }

    /// Qualify a path to absolute form. Idempotent.
    ///
    /// - `entity://peer/path` → `/peer/path`
    /// - `/peer/path` (already absolute) → as-is
    /// - `system/tree` (peer-relative) → `/{local_peer_id}/system/tree`
    /// - `*` (bare wildcard) → `/{local_peer_id}/*`
    ///
    /// Rejects reserved prefixes (`./`, `../`) and ambiguous `*/rest`.
    pub fn qualify_path(path: &str, local_peer_id: &str) -> String {
        // Strip entity:// scheme → produce absolute path
        if let Some(rest) = path.strip_prefix(URI_SCHEME) {
            return Self::clean_path(&format!("/{}", rest));
        }
        // Reject reserved directory-relative paths
        assert!(
            !path.starts_with("./") && !path.starts_with("../"),
            "reserved: directory-relative paths (./ and ../) are not yet supported"
        );
        // Reject ambiguous bare */rest — must use /*/rest
        assert!(
            !path.starts_with("*/"),
            "ambiguous: use /*/rest for peer wildcard patterns"
        );
        // Already absolute → pass through
        if path.starts_with('/') {
            return Self::clean_path(path);
        }
        // Bare wildcard → local peer all paths
        if path == "*" {
            return format!("/{}/*", local_peer_id);
        }
        // Defense-in-depth: legacy qualified path without leading /
        if let Some(slash) = path.find('/') {
            if Self::is_peer_id(&path[..slash]) {
                return format!("/{}", path);
            }
        } else if Self::is_peer_id(path) {
            return format!("/{}", path);
        }
        // Bare path → absolute with local peer
        format!("/{}/{}", local_peer_id, path)
    }

    /// Strip peer_id prefix from a qualified path.
    /// Returns the bare path portion.
    ///
    /// Handles both absolute (`/peer_id/rest` → `rest`) and legacy
    /// (`peer_id/rest` → `rest`) formats.
    pub fn strip_peer_prefix(path: &str) -> &str {
        // Strip leading / for absolute paths
        let p = path.strip_prefix('/').unwrap_or(path);
        if let Some(slash) = p.find('/') {
            if Self::is_peer_id(&p[..slash]) {
                return &p[slash + 1..];
            }
        }
        // Bare peer_id only (no path after)
        if Self::is_peer_id(p) {
            return "";
        }
        path
    }

    /// Check if a path is absolute (starts with `/`).
    pub fn is_absolute(path: &str) -> bool {
        path.starts_with('/')
    }

    /// Validate that a path is well-formed for dispatch (R12).
    ///
    /// Called **before** `qualify_path` at the protocol boundary.
    /// Returns `Err` with a description on failure.
    ///
    /// Rejects:
    /// - `./` and `../` prefixes (reserved for directory-relative)
    /// - Empty segments (`//`) in the path portion (not in `entity://` scheme)
    pub fn validate_path_input(path: &str) -> Result<(), String> {
        if path.starts_with("./") || path == "." {
            return Err("reserved: directory-relative path ./".into());
        }
        if path.starts_with("../") || path == ".." {
            return Err("reserved: directory-relative path ../".into());
        }
        // Check for empty segments — skip entity:// scheme
        let check_part = path.strip_prefix(URI_SCHEME).unwrap_or(path);
        if check_part.contains("//") {
            return Err("invalid: path contains empty segment (//)".into());
        }
        Ok(())
    }

    /// Validate that an absolute path has a valid structure (R12, R2).
    ///
    /// Called **after** `qualify_path` at the protocol boundary on tree paths
    /// (dispatch paths and resource targets). NOT called on patterns.
    ///
    /// Checks:
    /// - Starts with `/`
    /// - No empty segments (`//`)
    /// - First segment after `/` is a valid peer_id (Base58, >= 46 chars)
    ///
    /// **Strict — rejects `content` / `manifest` reserved words too** per
    /// `PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS §2.10`
    /// (D9). This rejection is load-bearing for the §6.4 collision-safety
    /// argument: a tree path's first segment is always a peer-ID, period.
    /// Reserved-word recognition for the `{X}`-slot URL form is a
    /// **separate URL-layer concern**; see [`Self::is_reserved_path_word`]
    /// for that helper. The two surfaces are deliberately distinct — the
    /// http-poll URL parser MAY accept reserved words; the entity tree
    /// path validator MUST NOT.
    pub fn validate_absolute_path(path: &str) -> Result<(), String> {
        if !path.starts_with('/') {
            return Err(format!("path is not absolute (no leading /): {}", path));
        }
        if path.contains("//") {
            return Err(format!("path contains empty segment (//): {}", path));
        }
        let after_slash = &path[1..]; // skip leading /
        let first_segment = match after_slash.find('/') {
            Some(idx) => &after_slash[..idx],
            None => after_slash,
        };
        if !Self::is_peer_id(first_segment) {
            return Err(format!(
                "first segment is not a valid peer_id: '{}' (expected Base58, 46 chars)",
                first_segment
            ));
        }
        Ok(())
    }

    /// True if `segment` is one of the `{X}`-slot reserved words (`content`
    /// or `manifest`).
    ///
    /// **URL-layer helper only** (`EXTENSION-NETWORK` §6.4 / D-12). This
    /// is NOT used by [`Self::validate_absolute_path`] — entity tree paths
    /// are strict-peer-ID per D9. Reserved-word redirects are an
    /// `http-poll` URL convention; the parser walking such URLs may use
    /// this helper to recognize the reserved-segment positions and
    /// redirect to content-store / manifest operations accordingly.
    /// Live `http` EXECUTEs the handler directly with no indirection.
    pub fn is_reserved_path_word(segment: &str) -> bool {
        matches!(segment, "content" | "manifest")
    }

    /// Clean a path: collapse consecutive `//` → `/`, preserve leading `/`,
    /// preserve trailing `/`. Handles `entity://` scheme transparently.
    ///
    /// Trailing slashes are data for tree prefix operations (they distinguish
    /// "subtree prefix" from "exact binding path" and are required by
    /// `tree.snapshot`, `tree.extract`, `tree.merge`). Callers that want a
    /// canonical binding path should strip trailing slashes themselves.
    ///
    /// Rejects reserved directory-relative prefixes (`./`, `../`).
    pub fn clean_path(input: &str) -> String {
        // Handle entity:// scheme — clean only the path portion
        if let Some(rest) = input.strip_prefix(URI_SCHEME) {
            return format!("{}{}", URI_SCHEME, Self::clean_path(rest));
        }
        // Reject reserved directory-relative prefixes
        assert!(
            !input.starts_with("./") && !input.starts_with("../"),
            "reserved: directory-relative paths (./ and ../) are not yet supported"
        );
        if input.is_empty() {
            return String::new();
        }
        // Collapse consecutive slashes, preserve leading and trailing /
        let mut result = String::with_capacity(input.len());
        let mut prev_slash = false;
        for ch in input.chars() {
            if ch == '/' {
                if !prev_slash {
                    result.push('/');
                }
                prev_slash = true;
            } else {
                result.push(ch);
                prev_slash = false;
            }
        }
        result
    }
}

impl std::fmt::Display for EntityUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}{}", URI_SCHEME, self.peer_id)
        } else {
            write!(f, "{}{}/{}", URI_SCHEME, self.peer_id, self.path)
        }
    }
}

#[derive(Debug, Error)]
pub enum EntityError {
    #[error("invalid entity type: {0}")]
    InvalidType(String),

    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: Hash, actual: Hash },

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid URI: {0}")]
    InvalidUri(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(s: &str) -> Vec<u8> {
        entity_ecf::to_ecf(&entity_ecf::text(s))
    }

    // --- Entity tests ---

    #[test]
    fn test_entity_new() {
        let e = Entity::new("test/type", make_data("hello")).unwrap();
        assert_eq!(e.entity_type, "test/type");
        assert!(!e.content_hash.is_zero());
    }

    #[test]
    fn test_entity_new_empty_type() {
        assert!(matches!(
            Entity::new("", make_data("hello")),
            Err(EntityError::InvalidType(_))
        ));
    }

    #[test]
    fn test_entity_new_empty_data() {
        assert!(matches!(
            Entity::new("test/type", vec![]),
            Err(EntityError::MissingField(_))
        ));
    }

    #[test]
    fn test_entity_validate_ok() {
        let e = Entity::new("test/type", make_data("hello")).unwrap();
        assert!(e.validate().is_ok());
    }

    #[test]
    fn test_entity_validate_tampered() {
        let mut e = Entity::new("test/type", make_data("hello")).unwrap();
        e.data = make_data("tampered");
        assert!(matches!(
            e.validate(),
            Err(EntityError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_entity_equality_by_hash() {
        let e1 = Entity::new("test/type", make_data("hello")).unwrap();
        let e2 = Entity::new("test/type", make_data("hello")).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_entity_different_data_not_equal() {
        let e1 = Entity::new("test/type", make_data("aaa")).unwrap();
        let e2 = Entity::new("test/type", make_data("bbb")).unwrap();
        assert_ne!(e1, e2);
    }

    // --- Envelope tests ---

    #[test]
    fn test_envelope_new() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let env = Envelope::new(root.clone());
        assert_eq!(env.root, root);
        assert!(env.included.is_empty());
    }

    #[test]
    fn test_envelope_include() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let extra_hash = extra.content_hash;
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.find_included(&extra_hash).is_some());
    }

    #[test]
    fn test_envelope_with_included() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let extra_hash = extra.content_hash;
        let mut map = BTreeMap::new();
        map.insert(extra.content_hash, extra);
        let env = Envelope::with_included(root, map);
        assert!(env.find_included(&extra_hash).is_some());
    }

    #[test]
    fn canonical_deletion_marker_hash_matches_spec() {
        // ENTITY-NATIVE-TYPE-SYSTEM §4.9 (v4.2.0) — implementations MUST
        // verify the canonical deletion-marker hash matches the value
        // pinned in the spec. Any deviation signals an ECF-encoding bug.
        let h = canonical_deletion_marker_hash();
        let hex_digest: String = h.digest().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex_digest, CANONICAL_DELETION_MARKER_HASH_HEX,
            "canonical deletion-marker hash MUST match the spec value"
        );
        // The data MUST be CBOR empty map (0xa0) — not 0x40 (empty bstr), not 0xf6 (null).
        let e = canonical_deletion_marker_entity();
        assert_eq!(e.data, vec![0xa0u8]);
        assert_eq!(e.entity_type, "system/deletion-marker");
    }

    #[test]
    fn test_envelope_validate_all() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let extra = Entity::new("test/extra", make_data("extra")).unwrap();
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.validate_all().is_ok());
    }

    #[test]
    fn test_envelope_validate_all_tampered() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let mut extra = Entity::new("test/extra", make_data("extra")).unwrap();
        extra.data = make_data("tampered");
        let mut env = Envelope::new(root);
        env.include(extra);
        assert!(env.validate_all().is_err());
    }

    #[test]
    fn test_envelope_find_signature_for() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let target_hash = root.content_hash;

        // Build a signature entity whose data has a "target" field = target_hash bytes
        let sig_data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("target"),
                entity_ecf::Value::Bytes(target_hash.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("signer"),
                entity_ecf::Value::Bytes(Hash::zero().to_bytes().to_vec()),
            ),
        ]));
        let sig_entity = Entity::new(TYPE_SIGNATURE, sig_data).unwrap();
        let mut env = Envelope::new(root);
        env.include(sig_entity);

        let found = env.find_signature_for(&target_hash);
        assert!(found.is_some());
        assert_eq!(found.unwrap().entity_type, TYPE_SIGNATURE);
    }

    #[test]
    fn test_envelope_find_signature_for_no_match() {
        let root = Entity::new("test/root", make_data("root")).unwrap();
        let env = Envelope::new(root);
        assert!(env.find_signature_for(&Hash::zero()).is_none());
    }

    // --- URI tests ---

    #[test]
    fn test_uri_parse_full() {
        let uri = EntityUri::parse("entity://abc123/system/tree").unwrap();
        assert_eq!(uri.peer_id, "abc123");
        assert_eq!(uri.path, "system/tree");
    }

    #[test]
    fn test_uri_parse_no_path() {
        let uri = EntityUri::parse("entity://abc123").unwrap();
        assert_eq!(uri.peer_id, "abc123");
        assert_eq!(uri.path, "");
    }

    #[test]
    fn test_uri_parse_invalid_scheme() {
        assert!(EntityUri::parse("http://abc123/path").is_err());
    }

    #[test]
    fn test_uri_display_roundtrip() {
        let uri = EntityUri::parse("entity://abc123/system/tree").unwrap();
        assert_eq!(uri.to_string(), "entity://abc123/system/tree");
    }

    #[test]
    fn test_uri_display_no_path() {
        let uri = EntityUri::parse("entity://abc123").unwrap();
        assert_eq!(uri.to_string(), "entity://abc123");
    }

    #[test]
    fn test_normalize_path_full_uri() {
        assert_eq!(
            EntityUri::normalize_path("entity://abc123/system/tree"),
            "system/tree"
        );
    }

    #[test]
    fn test_normalize_path_bare() {
        assert_eq!(EntityUri::normalize_path("system/tree"), "system/tree");
    }

    #[test]
    fn test_extract_handler_path() {
        assert_eq!(
            EntityUri::extract_handler_path("entity://alice/system/tree"),
            "system/tree"
        );
        assert_eq!(
            EntityUri::extract_handler_path("system/tree"),
            "system/tree"
        );
    }

    // --- is_peer_id tests ---

    #[test]
    fn test_is_peer_id_valid() {
        // A real Base58 46-char peer ID
        let peer_id = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        assert!(EntityUri::is_peer_id(peer_id.as_str()));
    }

    #[test]
    fn test_is_peer_id_invalid() {
        assert!(!EntityUri::is_peer_id("system"));
        assert!(!EntityUri::is_peer_id("short"));
        assert!(!EntityUri::is_peer_id("")); // too short
        // 46 chars with invalid Base58 char (0, O, I, l)
        assert!(!EntityUri::is_peer_id("0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    // --- qualify_path tests ---

    #[test]
    fn test_qualify_path_bare() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("system/tree", pid.as_str());
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_already_absolute() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let absolute = format!("/{}/system/tree", pid);
        let result = EntityUri::qualify_path(&absolute, pid.as_str());
        assert_eq!(result, absolute, "idempotent");
    }

    #[test]
    fn test_qualify_path_legacy_qualified() {
        // Legacy format without leading / — defense-in-depth upgrades it
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let legacy = format!("{}/system/tree", pid);
        let result = EntityUri::qualify_path(&legacy, pid.as_str());
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_entity_uri() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let uri = format!("entity://{}/system/tree", pid);
        let result = EntityUri::qualify_path(&uri, "other_peer_id_that_is_46chars_long12345678901");
        assert_eq!(result, format!("/{}/system/tree", pid));
    }

    #[test]
    fn test_qualify_path_bare_peer_id_only() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path(pid.as_str(), pid.as_str());
        assert_eq!(result, format!("/{}", pid), "bare peer_id becomes absolute");
    }

    #[test]
    fn test_qualify_path_bare_wildcard() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("*", pid.as_str());
        assert_eq!(result, format!("/{}/*", pid));
    }

    #[test]
    fn test_qualify_path_absolute_peer_wildcard() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let result = EntityUri::qualify_path("/*/system/tree", pid.as_str());
        assert_eq!(result, "/*/system/tree", "absolute peer wildcard passes through");
    }

    #[test]
    #[should_panic(expected = "ambiguous")]
    fn test_qualify_path_rejects_bare_star_slash() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        EntityUri::qualify_path("*/system/tree", pid.as_str());
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn test_qualify_path_rejects_dot_slash() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        EntityUri::qualify_path("./relative", pid.as_str());
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn test_qualify_path_rejects_dotdot_slash() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        EntityUri::qualify_path("../parent", pid.as_str());
    }

    // --- strip_peer_prefix tests ---

    #[test]
    fn test_strip_peer_prefix_absolute() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let absolute = format!("/{}/system/tree", pid);
        assert_eq!(EntityUri::strip_peer_prefix(&absolute), "system/tree");
    }

    #[test]
    fn test_strip_peer_prefix_legacy_qualified() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let legacy = format!("{}/system/tree", pid);
        assert_eq!(EntityUri::strip_peer_prefix(&legacy), "system/tree");
    }

    #[test]
    fn test_strip_peer_prefix_bare() {
        assert_eq!(EntityUri::strip_peer_prefix("system/tree"), "system/tree");
    }

    // --- clean_path tests ---

    #[test]
    fn test_clean_path_collapse_double_slash() {
        assert_eq!(EntityUri::clean_path("/peer//system/tree"), "/peer/system/tree");
    }

    #[test]
    fn test_clean_path_preserve_leading_slash() {
        assert_eq!(EntityUri::clean_path("/peer/system/tree"), "/peer/system/tree");
    }

    #[test]
    fn test_clean_path_preserves_trailing_slash() {
        // Trailing slash is data for tree prefix operations.
        assert_eq!(EntityUri::clean_path("/peer/path/"), "/peer/path/");
    }

    #[test]
    fn test_clean_path_root_only() {
        assert_eq!(EntityUri::clean_path("/"), "/");
    }

    #[test]
    fn test_clean_path_entity_scheme() {
        assert_eq!(
            EntityUri::clean_path("entity://peer//path"),
            "entity://peer/path"
        );
    }

    #[test]
    fn test_clean_path_bare_path() {
        assert_eq!(EntityUri::clean_path("system/tree"), "system/tree");
    }

    #[test]
    #[should_panic(expected = "reserved")]
    fn test_clean_path_rejects_dot_slash() {
        EntityUri::clean_path("./relative");
    }

    #[test]
    fn test_clean_path_dot_segments_ok() {
        // Segments starting with . are fine — only ./ and ../ at start are reserved
        assert_eq!(EntityUri::clean_path("/peer/.hidden/config"), "/peer/.hidden/config");
    }

    // --- is_absolute tests ---

    #[test]
    fn test_is_absolute() {
        assert!(EntityUri::is_absolute("/peer/system/tree"));
        assert!(EntityUri::is_absolute("/"));
        assert!(!EntityUri::is_absolute("system/tree"));
        assert!(!EntityUri::is_absolute(""));
    }

    // --- validate_path_input tests ---

    #[test]
    fn test_validate_path_input_ok() {
        assert!(EntityUri::validate_path_input("system/tree").is_ok());
        assert!(EntityUri::validate_path_input("/peer/system/tree").is_ok());
        assert!(EntityUri::validate_path_input("entity://peer/path").is_ok());
        assert!(EntityUri::validate_path_input(".hidden/config").is_ok()); // dot segment, not ./
    }

    #[test]
    fn test_validate_path_input_rejects_dot_slash() {
        assert!(EntityUri::validate_path_input("./relative").is_err());
        assert!(EntityUri::validate_path_input(".").is_err());
    }

    #[test]
    fn test_validate_path_input_rejects_dotdot_slash() {
        assert!(EntityUri::validate_path_input("../parent").is_err());
        assert!(EntityUri::validate_path_input("..").is_err());
    }

    #[test]
    fn test_validate_path_input_rejects_empty_segment() {
        assert!(EntityUri::validate_path_input("system//tree").is_err());
        assert!(EntityUri::validate_path_input("//peer/path").is_err());
    }

    // --- validate_absolute_path tests ---

    #[test]
    fn test_validate_absolute_path_ok() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}/system/tree", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_ok());
    }

    #[test]
    fn test_validate_absolute_path_bare_peer() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_ok());
    }

    #[test]
    fn test_validate_absolute_path_not_absolute() {
        assert!(EntityUri::validate_absolute_path("system/tree").is_err());
    }

    #[test]
    fn test_validate_absolute_path_empty_segment() {
        let pid = entity_crypto::Keypair::from_seed([42u8; 32]).peer_id();
        let path = format!("/{}//system/tree", pid);
        assert!(EntityUri::validate_absolute_path(&path).is_err());
    }

    #[test]
    fn test_validate_absolute_path_invalid_peer_id() {
        assert!(EntityUri::validate_absolute_path("/notapeerid/system/tree").is_err());
    }

    #[test]
    fn test_validate_absolute_path_short_segment() {
        assert!(EntityUri::validate_absolute_path("/abc/system/tree").is_err());
    }

    // --- D9 (PROPOSAL-TRANSPORT-FAMILY-CHUNK-C-AMENDMENTS §2.10):
    //     validate_absolute_path stays STRICT — reserved-word recognition
    //     is a SEPARATE URL-layer helper. The strict rejection is
    //     load-bearing for the §6.4 collision-safety argument.

    #[test]
    fn test_validate_absolute_path_rejects_reserved_words() {
        // `content` and `manifest` are URL-layer reserved words for the
        // http-poll `{X}` slot, NOT valid entity-tree-path first segments.
        // The entity tree path validator MUST reject them.
        assert!(EntityUri::validate_absolute_path("/content").is_err());
        assert!(EntityUri::validate_absolute_path("/content/00aa").is_err());
        assert!(EntityUri::validate_absolute_path("/manifest").is_err());
        assert!(EntityUri::validate_absolute_path("/manifest/current").is_err());
    }

    #[test]
    fn test_validate_absolute_path_rejects_arbitrary_short_word() {
        assert!(EntityUri::validate_absolute_path("/system/tree").is_err());
        assert!(EntityUri::validate_absolute_path("/peers/foo").is_err());
    }

    #[test]
    fn test_is_reserved_path_word_helper_intact() {
        // The URL-layer helper is independent of validate_absolute_path;
        // recognizes the {X}-slot reserved words for http-poll URL
        // parsing. Decoupled per D9.
        assert!(EntityUri::is_reserved_path_word("content"));
        assert!(EntityUri::is_reserved_path_word("manifest"));
        assert!(!EntityUri::is_reserved_path_word("Content"));
        assert!(!EntityUri::is_reserved_path_word("manifests"));
        assert!(!EntityUri::is_reserved_path_word(""));
    }
}
