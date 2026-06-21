//! Shared test functions for ContentStore and LocationIndex implementations.
//!
//! Each function takes a trait object so the same test logic runs against
//! Memory, SQLite, and any future backend.

use crate::{CasError, ContentStore, LocationIndex};
use entity_entity::Entity;
use entity_hash::Hash;

pub fn make_entity(type_str: &str, data_str: &str) -> Entity {
    let data = entity_ecf::to_ecf(&entity_ecf::text(data_str));
    Entity::new(type_str, data).unwrap()
}

// --- ContentStore tests ---

pub fn test_content_store_put_get(cs: &dyn ContentStore) {
    let entity = make_entity("test/type", "hello");
    let hash = cs.put(entity.clone()).unwrap();
    let retrieved = cs.get(&hash).unwrap();
    assert_eq!(retrieved.content_hash, entity.content_hash);
    assert_eq!(retrieved.entity_type, "test/type");
}

pub fn test_content_store_has(cs: &dyn ContentStore) {
    let entity = make_entity("test/type", "hello");
    let hash = entity.content_hash;
    assert!(!cs.has(&hash));
    cs.put(entity).unwrap();
    assert!(cs.has(&hash));
}

pub fn test_content_store_remove(cs: &dyn ContentStore) {
    let entity = make_entity("test/type", "hello");
    let hash = entity.content_hash;
    cs.put(entity).unwrap();
    assert!(cs.remove(&hash));
    assert!(!cs.has(&hash));
    assert!(!cs.remove(&hash));
}

pub fn test_content_store_len(cs: &dyn ContentStore) {
    assert_eq!(cs.len(), 0);
    assert!(cs.is_empty());
    cs.put(make_entity("test/a", "aaa")).unwrap();
    cs.put(make_entity("test/b", "bbb")).unwrap();
    assert_eq!(cs.len(), 2);
    assert!(!cs.is_empty());
}

pub fn test_content_store_get_missing(cs: &dyn ContentStore) {
    assert!(cs.get(&Hash::zero()).is_none());
}

pub fn test_content_store_put_overwrite(cs: &dyn ContentStore) {
    let entity = make_entity("test/type", "hello");
    cs.put(entity.clone()).unwrap();
    cs.put(entity.clone()).unwrap();
    assert_eq!(cs.len(), 1);
}

pub fn test_content_store_multiple_entities(cs: &dyn ContentStore) {
    let e1 = make_entity("test/a", "alpha");
    let e2 = make_entity("test/b", "beta");
    let e3 = make_entity("test/c", "gamma");
    let h1 = cs.put(e1).unwrap();
    let h2 = cs.put(e2).unwrap();
    let h3 = cs.put(e3).unwrap();
    assert_eq!(cs.len(), 3);
    assert!(cs.get(&h1).is_some());
    assert!(cs.get(&h2).is_some());
    assert!(cs.get(&h3).is_some());
}

// --- LocationIndex tests ---

pub fn test_location_index_set_get(li: &dyn LocationIndex) {
    let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
    li.set("system/tree", hash);
    assert_eq!(li.get("system/tree"), Some(hash));
}

pub fn test_location_index_has(li: &dyn LocationIndex) {
    assert!(!li.has("system/tree"));
    let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
    li.set("system/tree", hash);
    assert!(li.has("system/tree"));
}

pub fn test_location_index_remove(li: &dyn LocationIndex) {
    let hash = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("x")));
    li.set("system/tree", hash);
    let removed = li.remove("system/tree");
    assert_eq!(removed, Some(hash));
    assert!(!li.has("system/tree"));
    assert!(li.remove("system/tree").is_none());
}

pub fn test_location_index_get_missing(li: &dyn LocationIndex) {
    assert!(li.get("nonexistent").is_none());
}

pub fn test_location_index_overwrite(li: &dyn LocationIndex) {
    let h1 = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("one")));
    let h2 = Hash::compute("test", &entity_ecf::to_ecf(&entity_ecf::text("two")));
    li.set("path", h1);
    li.set("path", h2);
    assert_eq!(li.get("path"), Some(h2));
}

pub fn test_location_index_list_prefix(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));
    let h3 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("3")));
    li.set("system/handler/a", h1);
    li.set("system/handler/b", h2);
    li.set("system/tree", h3);

    let entries = li.list("system/handler/");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "system/handler/a");
    assert_eq!(entries[1].path, "system/handler/b");
}

pub fn test_location_index_list_all(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));
    li.set("a/path", h1);
    li.set("b/path", h2);

    let entries = li.list("");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path, "a/path");
    assert_eq!(entries[1].path, "b/path");
}

pub fn test_location_index_list_empty(li: &dyn LocationIndex) {
    let entries = li.list("system/");
    assert!(entries.is_empty());
}

pub fn test_location_index_list_no_match(li: &dyn LocationIndex) {
    let hash = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("x")));
    li.set("other/path", hash);
    let entries = li.list("system/");
    assert!(entries.is_empty());
}

pub fn test_location_index_len_prefix(li: &dyn LocationIndex) {
    assert_eq!(li.len_prefix(""), 0);
    assert_eq!(li.len_prefix("system/"), 0);

    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("2")));
    let h3 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("3")));
    li.set("system/handler/a", h1);
    li.set("system/handler/b", h2);
    li.set("other/path", h3);

    // Empty prefix counts everything.
    assert_eq!(li.len_prefix(""), 3);
    // Non-empty prefix counts only matches.
    assert_eq!(li.len_prefix("system/handler/"), 2);
    assert_eq!(li.len_prefix("system/"), 2);
    assert_eq!(li.len_prefix("other/"), 1);
    // Non-matching prefix returns 0.
    assert_eq!(li.len_prefix("nope/"), 0);

    // Remove updates the count.
    li.remove("system/handler/a");
    assert_eq!(li.len_prefix(""), 2);
    assert_eq!(li.len_prefix("system/handler/"), 1);
}

// --- LocationIndex CAS tests (ENTITY-CORE-PROTOCOL §3.9) ---

pub fn test_cas_swap_match_succeeds(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v2")));
    li.set("cas/path", h1);
    assert_eq!(li.compare_and_swap("cas/path", h1, h2), Ok(()));
    assert_eq!(li.get("cas/path"), Some(h2));
}

pub fn test_cas_swap_mismatch_returns_actual(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v2")));
    let h3 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v3")));
    li.set("cas/path", h1);
    assert_eq!(
        li.compare_and_swap("cas/path", h2, h3),
        Err(CasError::Mismatch(h1))
    );
    // Binding unchanged after failed CAS
    assert_eq!(li.get("cas/path"), Some(h1));
}

pub fn test_cas_swap_missing_returns_not_found(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v2")));
    assert_eq!(
        li.compare_and_swap("cas/missing", h1, h2),
        Err(CasError::NotFound)
    );
}

pub fn test_cas_remove_match_succeeds(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    li.set("cas/path", h1);
    assert_eq!(li.compare_and_remove("cas/path", h1), Ok(h1));
    assert!(li.get("cas/path").is_none());
}

pub fn test_cas_remove_mismatch_returns_actual(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    let h2 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v2")));
    li.set("cas/path", h1);
    assert_eq!(
        li.compare_and_remove("cas/path", h2),
        Err(CasError::Mismatch(h1))
    );
    assert_eq!(li.get("cas/path"), Some(h1));
}

pub fn test_cas_remove_missing_returns_not_found(li: &dyn LocationIndex) {
    let h1 = Hash::compute("t", &entity_ecf::to_ecf(&entity_ecf::text("v1")));
    assert_eq!(
        li.compare_and_remove("cas/missing", h1),
        Err(CasError::NotFound)
    );
}
