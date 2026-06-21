//! Generic handle table for opaque FFI handles.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use crate::types::Handle;

/// A thread-safe handle table mapping u64 handles to values.
pub struct HandleMap<T> {
    next: AtomicU64,
    map: RwLock<HashMap<u64, T>>,
}

impl<T> HandleMap<T> {
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1), // 0 = invalid handle
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Insert a value and return its handle.
    pub fn insert(&self, value: T) -> Handle {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.map.write().unwrap().insert(id, value);
        id
    }

    /// Get a reference to the value, executing a closure with it.
    pub fn with<R, F: FnOnce(&T) -> R>(&self, handle: Handle, f: F) -> Option<R> {
        let map = self.map.read().unwrap();
        map.get(&handle).map(f)
    }

    /// Get a mutable reference to the value, executing a closure with it.
    pub fn with_mut<R, F: FnOnce(&mut T) -> R>(&self, handle: Handle, f: F) -> Option<R> {
        let mut map = self.map.write().unwrap();
        map.get_mut(&handle).map(f)
    }

    /// Remove and return a value.
    pub fn remove(&self, handle: Handle) -> Option<T> {
        self.map.write().unwrap().remove(&handle)
    }
}
