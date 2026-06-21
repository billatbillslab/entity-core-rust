//! Domain type definitions for `local/files/*` (DOMAIN-LOCAL-FILES §2,
//! §3.2, §3.3). Domain types are not bootstrap (§11) — they're written
//! into the tree at handler-install time, mirroring the Go reference
//! impl's `RegisterTypes`. Persistence makes them visible to remote
//! peers walking `system/type/local/files/*` for validation.

use entity_types::{FieldSpec, TypeDefBuilder, TypeDefinition};

fn t(name: &str) -> FieldSpec {
    FieldSpec::type_ref(name)
}
fn opt(name: &str) -> FieldSpec {
    FieldSpec::optional(name)
}
fn arr(element: FieldSpec) -> FieldSpec {
    FieldSpec::array(element)
}
fn opt_arr(element: FieldSpec) -> FieldSpec {
    FieldSpec::optional_array(element)
}

fn file() -> TypeDefinition {
    TypeDefBuilder::new("local/files/file")
        .field("path", t("primitive/string"))
        .field("size", t("primitive/uint"))
        .field("modified_at", opt("primitive/uint"))
        .field("content", t("system/hash"))
        .field("media_type", opt("primitive/string"))
        .field("written", opt("primitive/bool"))
        .build()
}

fn directory() -> TypeDefinition {
    TypeDefBuilder::new("local/files/directory")
        .field("path", t("primitive/string"))
        .field("children", opt_arr(t("local/files/directory/entry")))
        .field("modified_at", opt("primitive/uint"))
        .build()
}

fn directory_entry() -> TypeDefinition {
    TypeDefBuilder::new("local/files/directory/entry")
        .field("name", t("primitive/string"))
        .field("entity_path", t("system/tree/path"))
        .field("entry_type", t("primitive/string"))
        .field("size", opt("primitive/uint"))
        .field("modified_at", opt("primitive/uint"))
        .build()
}

fn deleted() -> TypeDefinition {
    TypeDefBuilder::new("local/files/deleted")
        .field("path", t("primitive/string"))
        .field("existed", t("primitive/bool"))
        .build()
}

fn root_config() -> TypeDefinition {
    TypeDefBuilder::new("local/files/root-config")
        .field("prefix", t("system/tree/path"))
        .field("filesystem_root", t("primitive/string"))
        .field("read_only", opt("primitive/bool"))
        .field("exclude", opt_arr(t("primitive/string")))
        .field("include", opt_arr(t("primitive/string")))
        .field("publish_descriptors", opt("primitive/bool"))
        .build()
}

fn watcher_config() -> TypeDefinition {
    TypeDefBuilder::new("local/files/watcher-config")
        .field("root_name", t("primitive/string"))
        .field("status", t("primitive/string"))
        .field("debounce_ms", opt("primitive/uint"))
        .field("error_message", opt("primitive/string"))
        .build()
}

fn write_request() -> TypeDefinition {
    TypeDefBuilder::new("local/files/write-request")
        .field("bytes", opt("primitive/bytes"))
        .field("content", opt("system/hash"))
        .field("media_type", opt("primitive/string"))
        .field("create_dirs", opt("primitive/bool"))
        .build()
}

fn watch_request() -> TypeDefinition {
    TypeDefBuilder::new("local/files/watch-request")
        .field("root_name", t("primitive/string"))
        .field("action", opt("primitive/string"))
        .field("debounce_ms", opt("primitive/uint"))
        .build()
}

/// All 8 domain type definitions (§11 — registered at handler install).
pub fn all_domain_types() -> Vec<TypeDefinition> {
    vec![
        directory_entry(),
        file(),
        directory(),
        deleted(),
        root_config(),
        watcher_config(),
        write_request(),
        watch_request(),
    ]
}

// Silence unused-arr lint when `arr` isn't reached by the optimizer.
#[allow(dead_code)]
fn _silence_unused() {
    let _ = arr(t("x"));
}
