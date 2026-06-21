//! DOMAIN-LOCAL-FILES v1.2 §2 — type names, entity construction, and
//! decoding helpers for the local/files domain types.
//!
//! All entities follow the typed-struct field-wire convention: `core/entity`
//! wrapping fields (the `data` carrying the records below) are flat CBOR
//! maps; only `result` / `params` carry the `{type, data, content_hash}`
//! envelope. This matches the Go reference impl and the Rust attestation /
//! identity precedents.

use ciborium::Value;
use entity_ecf::{text, to_ecf, ValueExt};
use entity_entity::Entity;
use entity_hash::Hash;

pub const TYPE_FILE: &str = "local/files/file";
pub const TYPE_DIRECTORY: &str = "local/files/directory";
pub const TYPE_DIRECTORY_ENTRY: &str = "local/files/directory/entry";
pub const TYPE_DELETED: &str = "local/files/deleted";
pub const TYPE_ROOT_CONFIG: &str = "local/files/root-config";
pub const TYPE_WATCHER_CONFIG: &str = "local/files/watcher-config";
pub const TYPE_WRITE_REQUEST: &str = "local/files/write-request";
pub const TYPE_WATCH_REQUEST: &str = "local/files/watch-request";

/// §2.1 — file entity.
#[derive(Debug, Clone)]
pub struct FileData {
    pub path: String,
    pub size: u64,
    pub modified_at: Option<u64>,
    pub content: Hash,
    pub media_type: Option<String>,
    pub written: bool,
}

impl FileData {
    pub fn to_entity(&self) -> Result<Entity, String> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(6);
        entries.push((text("path"), text(self.path.clone())));
        entries.push((text("size"), Value::Integer(self.size.into())));
        if let Some(m) = self.modified_at {
            entries.push((text("modified_at"), Value::Integer(m.into())));
        }
        entries.push((text("content"), hash_to_record(&self.content)));
        if let Some(ref mt) = self.media_type {
            entries.push((text("media_type"), text(mt.clone())));
        }
        if self.written {
            entries.push((text("written"), Value::Bool(true)));
        }
        let data = to_ecf(&Value::Map(entries));
        Entity::new(TYPE_FILE, data).map_err(|e| e.to_string())
    }
}

/// §2.2 — directory listing.
#[derive(Debug, Clone)]
pub struct DirectoryData {
    pub path: String,
    pub children: Vec<DirectoryEntryData>,
    pub modified_at: Option<u64>,
}

impl DirectoryData {
    pub fn to_entity(&self) -> Result<Entity, String> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(3);
        entries.push((text("path"), text(self.path.clone())));
        if !self.children.is_empty() {
            let arr = Value::Array(self.children.iter().map(directory_entry_to_value).collect());
            entries.push((text("children"), arr));
        }
        if let Some(m) = self.modified_at {
            entries.push((text("modified_at"), Value::Integer(m.into())));
        }
        let data = to_ecf(&Value::Map(entries));
        Entity::new(TYPE_DIRECTORY, data).map_err(|e| e.to_string())
    }
}

/// §2.3 — directory entry within a listing.
#[derive(Debug, Clone)]
pub struct DirectoryEntryData {
    pub name: String,
    pub entity_path: String,
    pub entry_type: String,
    pub size: Option<u64>,
    pub modified_at: Option<u64>,
}

fn directory_entry_to_value(e: &DirectoryEntryData) -> Value {
    let mut entries: Vec<(Value, Value)> = Vec::with_capacity(5);
    entries.push((text("name"), text(e.name.clone())));
    entries.push((text("entity_path"), text(e.entity_path.clone())));
    entries.push((text("entry_type"), text(e.entry_type.clone())));
    if let Some(s) = e.size {
        entries.push((text("size"), Value::Integer(s.into())));
    }
    if let Some(m) = e.modified_at {
        entries.push((text("modified_at"), Value::Integer(m.into())));
    }
    Value::Map(entries)
}

/// §2.4 — deletion confirmation.
#[derive(Debug, Clone)]
pub struct DeletedData {
    pub path: String,
    pub existed: bool,
}

impl DeletedData {
    pub fn to_entity(&self) -> Result<Entity, String> {
        let data = to_ecf(&Value::Map(vec![
            (text("path"), text(self.path.clone())),
            (text("existed"), Value::Bool(self.existed)),
        ]));
        Entity::new(TYPE_DELETED, data).map_err(|e| e.to_string())
    }
}

/// §2.5 — root mapping configuration.
#[derive(Debug, Clone, Default)]
pub struct RootConfigData {
    pub prefix: String,
    pub filesystem_root: String,
    pub read_only: bool,
    pub exclude: Vec<String>,
    pub include: Vec<String>,
    pub publish_descriptors: bool,
}

impl RootConfigData {
    pub fn to_entity(&self) -> Result<Entity, String> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(6);
        entries.push((text("prefix"), text(self.prefix.clone())));
        entries.push((text("filesystem_root"), text(self.filesystem_root.clone())));
        if self.read_only {
            entries.push((text("read_only"), Value::Bool(true)));
        }
        if !self.exclude.is_empty() {
            entries.push((
                text("exclude"),
                Value::Array(self.exclude.iter().cloned().map(text).collect()),
            ));
        }
        if !self.include.is_empty() {
            entries.push((
                text("include"),
                Value::Array(self.include.iter().cloned().map(text).collect()),
            ));
        }
        if self.publish_descriptors {
            entries.push((text("publish_descriptors"), Value::Bool(true)));
        }
        let data = to_ecf(&Value::Map(entries));
        Entity::new(TYPE_ROOT_CONFIG, data).map_err(|e| e.to_string())
    }

    pub fn from_entity(e: &Entity) -> Result<Self, String> {
        let v: Value = ciborium::from_reader(e.data.as_slice())
            .map_err(|err| format!("cbor: {err}"))?;
        let mut out = RootConfigData::default();
        out.prefix = v.get("prefix").and_then(|x| x.as_text().map(String::from)).unwrap_or_default();
        out.filesystem_root = v
            .get("filesystem_root")
            .and_then(|x| x.as_text().map(String::from))
            .unwrap_or_default();
        out.read_only = v.get("read_only").and_then(|x| x.as_bool()).unwrap_or(false);
        out.exclude = string_array(v.get("exclude"));
        out.include = string_array(v.get("include"));
        out.publish_descriptors = v
            .get("publish_descriptors")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        Ok(out)
    }
}

/// §2.6 — file watcher configuration.
#[derive(Debug, Clone)]
pub struct WatcherConfigData {
    pub root_name: String,
    pub status: String,
    pub debounce_ms: Option<u64>,
    pub error_message: Option<String>,
}

impl WatcherConfigData {
    pub fn to_entity(&self) -> Result<Entity, String> {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(4);
        entries.push((text("root_name"), text(self.root_name.clone())));
        entries.push((text("status"), text(self.status.clone())));
        if let Some(d) = self.debounce_ms {
            entries.push((text("debounce_ms"), Value::Integer(d.into())));
        }
        if let Some(ref msg) = self.error_message {
            entries.push((text("error_message"), text(msg.clone())));
        }
        let data = to_ecf(&Value::Map(entries));
        Entity::new(TYPE_WATCHER_CONFIG, data).map_err(|e| e.to_string())
    }
}

/// §3.2 — write-request params.
#[derive(Debug, Clone, Default)]
pub struct WriteRequestData {
    pub bytes: Option<Vec<u8>>,
    pub content: Option<Hash>,
    pub media_type: Option<String>,
    pub create_dirs: bool,
}

impl WriteRequestData {
    pub fn from_params(e: &Entity) -> Result<Self, String> {
        let v: Value = ciborium::from_reader(e.data.as_slice())
            .map_err(|err| format!("cbor: {err}"))?;
        let mut out = WriteRequestData::default();
        out.bytes = v.get("bytes").and_then(|x| x.as_bytes().cloned());
        out.content = match v.get("content") {
            Some(Value::Null) | None => None,
            Some(h) => Some(decode_hash_record(h)?),
        };
        out.media_type = v.get("media_type").and_then(|x| x.as_text().map(String::from));
        out.create_dirs = v.get("create_dirs").and_then(|x| x.as_bool()).unwrap_or(false);
        Ok(out)
    }
}

/// §3.3 — watch-request params.
#[derive(Debug, Clone, Default)]
pub struct WatchRequestData {
    pub root_name: String,
    pub action: Option<String>,
    pub debounce_ms: Option<u64>,
}

impl WatchRequestData {
    pub fn from_params(e: &Entity) -> Result<Self, String> {
        let v: Value = ciborium::from_reader(e.data.as_slice())
            .map_err(|err| format!("cbor: {err}"))?;
        let mut out = WatchRequestData::default();
        out.root_name = v
            .get("root_name")
            .and_then(|x| x.as_text().map(String::from))
            .unwrap_or_default();
        out.action = v.get("action").and_then(|x| x.as_text().map(String::from));
        out.debounce_ms = v.get("debounce_ms").and_then(value_to_u64);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a `Hash` as the **single-field** wire form: a 33-byte CBOR
/// bstr (algorithm || digest). Used for `system/hash` fields embedded
/// directly in typed structs (e.g., `FileData.content`,
/// `WriteRequestData.content`). Arrays of `system/hash` use the flat
/// record form `{format_code, digest}` per ENTITY-NATIVE-TYPE-SYSTEM
/// §2.8 — that's a separate code path.
pub(crate) fn hash_to_record(h: &Hash) -> Value {
    Value::Bytes(h.to_bytes())
}

pub(crate) fn decode_hash_record(v: &Value) -> Result<Hash, String> {
    let bytes = v
        .as_bytes()
        .ok_or_else(|| "hash field not a bstr".to_string())?;
    Hash::from_bytes(bytes).map_err(|e| e.to_string())
}

#[allow(dead_code)]
pub(crate) fn value_to_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => (*i).try_into().ok(),
        _ => None,
    }
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(|x| x.as_array().cloned())
        .map(|arr| arr.iter().filter_map(|e| e.as_text().map(String::from)).collect())
        .unwrap_or_default()
}
