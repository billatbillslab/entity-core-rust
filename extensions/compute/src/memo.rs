use std::collections::HashMap;
use std::sync::RwLock;

use entity_hash::Hash;

use crate::types::*;

/// Memoization table for pure expressions (§4.6).
///
/// Keyed on (expression_hash, scope_hash) to handle scope-dependent results.
/// Only pure expressions are memoized — impure expressions (tree lookup,
/// handler dispatch) are never cached.
pub struct MemoTable {
    entries: RwLock<HashMap<(Hash, Hash), Hash>>,
    max_size: usize,
}

impl MemoTable {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_size,
        }
    }

    pub fn get(&self, expression_hash: &Hash, scope_hash: &Hash) -> Option<Hash> {
        let map = self.entries.read().unwrap();
        map.get(&(*expression_hash, *scope_hash)).copied()
    }

    pub fn insert(&self, expression_hash: Hash, scope_hash: Hash, result_hash: Hash) {
        let mut map = self.entries.write().unwrap();
        if map.len() >= self.max_size {
            map.clear();
        }
        map.insert((expression_hash, scope_hash), result_hash);
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.entries.write().unwrap().clear();
    }
}

const DEFAULT_MEMO_SIZE: usize = 10_000;

impl Default for MemoTable {
    fn default() -> Self {
        Self::new(DEFAULT_MEMO_SIZE)
    }
}

/// Check if an entity type is pure (§6.1).
///
/// An expression is pure if it and all subexpressions are pure.
/// This checks the top-level type only — full purity requires walking the graph.
pub fn is_pure_type(entity_type: &str) -> bool {
    matches!(
        entity_type,
        TYPE_LITERAL
            | TYPE_LOOKUP_SCOPE
            | TYPE_LAMBDA
            | TYPE_ARITHMETIC
            | TYPE_COMPARE
            | TYPE_LOGIC
            | TYPE_FIELD
            | TYPE_CONSTRUCT
            | TYPE_INDEX
            | TYPE_LENGTH
            | TYPE_NUMERIC_CAST
    )
}

/// Compute a scope hash for memoization key (§4.6).
///
/// Serializes scope bindings in sorted order and hashes the result.
pub fn scope_hash(scope: &Scope) -> Hash {
    if scope.bindings.is_empty() {
        return Hash::compute(TYPE_SCOPE, b"empty");
    }

    let mut entries: Vec<(ciborium::Value, ciborium::Value)> = Vec::new();
    for (name, value) in &scope.bindings {
        let cbor_val = match value {
            ComputeValue::Primitive(v) => v.clone(),
            ComputeValue::Entity(e) => {
                ciborium::Value::Bytes(e.content_hash.to_bytes().to_vec())
            }
            ComputeValue::Closure(c) => {
                ciborium::Value::Bytes(c.to_entity().content_hash.to_bytes().to_vec())
            }
            ComputeValue::Error(err) => {
                ciborium::Value::Bytes(err.to_entity().content_hash.to_bytes().to_vec())
            }
            ComputeValue::Uint(u) => {
                ciborium::Value::Integer(ciborium::value::Integer::from(*u))
            }
        };
        entries.push((ciborium::Value::Text(name.clone()), cbor_val));
    }

    let map = ciborium::Value::Map(entries);
    let encoded = entity_ecf::to_ecf(&map);
    Hash::compute(TYPE_SCOPE, &encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memo_insert_get() {
        let memo = MemoTable::new(100);
        let expr_h = Hash::compute("test", b"expr");
        let scope_h = Hash::compute("test", b"scope");
        let result_h = Hash::compute("test", b"result");

        assert!(memo.get(&expr_h, &scope_h).is_none());

        memo.insert(expr_h, scope_h, result_h);
        assert_eq!(memo.get(&expr_h, &scope_h), Some(result_h));
    }

    #[test]
    fn test_memo_scope_matters() {
        let memo = MemoTable::new(100);
        let expr_h = Hash::compute("test", b"expr");
        let scope1 = Hash::compute("test", b"scope1");
        let scope2 = Hash::compute("test", b"scope2");
        let result1 = Hash::compute("test", b"result1");
        let result2 = Hash::compute("test", b"result2");

        memo.insert(expr_h, scope1, result1);
        memo.insert(expr_h, scope2, result2);

        assert_eq!(memo.get(&expr_h, &scope1), Some(result1));
        assert_eq!(memo.get(&expr_h, &scope2), Some(result2));
    }

    #[test]
    fn test_memo_eviction() {
        let memo = MemoTable::new(2);
        let h1 = Hash::compute("test", b"1");
        let h2 = Hash::compute("test", b"2");
        let h3 = Hash::compute("test", b"3");
        let empty_scope = Hash::compute("test", b"empty");

        memo.insert(h1, empty_scope, h1);
        memo.insert(h2, empty_scope, h2);
        assert_eq!(memo.len(), 2);

        // Third insert triggers clear
        memo.insert(h3, empty_scope, h3);
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn test_is_pure_type() {
        assert!(is_pure_type(TYPE_LITERAL));
        assert!(is_pure_type(TYPE_ARITHMETIC));
        assert!(is_pure_type(TYPE_LOOKUP_SCOPE));
        assert!(!is_pure_type(TYPE_LOOKUP_TREE));
        assert!(!is_pure_type(TYPE_APPLY));
    }

    #[test]
    fn test_scope_hash_deterministic() {
        let mut scope = Scope::new();
        scope.set("x".into(), ComputeValue::Primitive(entity_ecf::integer(5)));
        scope.set("y".into(), ComputeValue::Primitive(entity_ecf::integer(10)));

        let h1 = scope_hash(&scope);
        let h2 = scope_hash(&scope);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_scope_hash_empty() {
        let scope = Scope::new();
        let h = scope_hash(&scope);
        assert_ne!(h.digest(), [0u8; 32]);
    }
}
