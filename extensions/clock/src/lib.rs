//! system/clock handler — now + compare + tick operations.
//!
//! Provides wall-clock timestamps, logical clocks, vector clocks, and HLC
//! (hybrid logical clocks). Clock advances on tree writes via the engine.

pub mod engine;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use entity_entity::Entity;
use entity_handler::{
    Handler, HandlerContext, HandlerError, HandlerResult, STATUS_BAD_REQUEST, STATUS_NOT_SUPPORTED,
    STATUS_OK,
};
use entity_hash::Hash;
use entity_store::{ContentStore, LocationIndex};

/// The clock handler: system/clock with now, compare, tick operations.
pub struct ClockHandler {
    content_store: Arc<dyn ContentStore>,
    location_index: Arc<dyn LocationIndex>,
    local_peer_id: String,
    qualified_pattern: String,
}

impl ClockHandler {
    pub fn new(
        content_store: Arc<dyn ContentStore>,
        location_index: Arc<dyn LocationIndex>,
        local_peer_id: String,
    ) -> Self {
        let qualified_pattern = format!("/{}/system/clock", local_peer_id);
        Self {
            content_store,
            location_index,
            local_peer_id,
            qualified_pattern,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl Handler for ClockHandler {
    async fn handle(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        match ctx.operation.as_str() {
            "now" => self.handle_now(ctx).await,
            "compare" => self.handle_compare(ctx).await,
            "tick" => Ok(error_result(
                STATUS_NOT_SUPPORTED,
                "not_implemented",
                "tick operation not yet implemented",
            )),
            _ => Ok(error_result(
                STATUS_BAD_REQUEST,
                "unknown_operation",
                &format!("unknown: {}", ctx.operation),
            )),
        }
    }

    fn pattern(&self) -> &str {
        &self.qualified_pattern
    }

    fn name(&self) -> &str {
        "clock"
    }

    fn operations(&self) -> &[&str] {
        &["now", "compare", "tick"]
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ClockConfig {
    pub(crate) mode: String,
    pub(crate) wall_clock: bool,
}

fn default_config() -> ClockConfig {
    ClockConfig {
        mode: engine::DEFAULT_CLOCK_MODE.to_string(),
        wall_clock: true,
    }
}

pub(crate) fn read_config(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> ClockConfig {
    let config_path = format!("/{}/system/clock/config", local_peer_id);
    let hash = match location_index.get(&config_path) {
        Some(h) => h,
        None => return default_config(),
    };
    let entity = match content_store.get(&hash) {
        Some(e) => e,
        None => return default_config(),
    };
    let val: ciborium::Value = match ciborium::from_reader(entity.data.as_slice()) {
        Ok(v) => v,
        Err(_) => return default_config(),
    };
    let map = match val.as_map() {
        Some(m) => m,
        None => return default_config(),
    };

    let mut mode = engine::DEFAULT_CLOCK_MODE.to_string();
    let mut wall_clock = true;

    for (k, v) in map {
        match k.as_text() {
            Some("mode") => {
                if let Some(s) = v.as_text() {
                    mode = s.to_string();
                }
            }
            Some("wall_clock") => {
                if let Some(b) = v.as_bool() {
                    wall_clock = b;
                }
            }
            _ => {}
        }
    }

    ClockConfig { mode, wall_clock }
}

// ---------------------------------------------------------------------------
// now operation (§3.2)
// ---------------------------------------------------------------------------

impl ClockHandler {
    async fn handle_now(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        tracing::debug!(request_id = %ctx.request_id, "clock: now");
        let config = read_config(self.content_store.as_ref(), self.location_index.as_ref(), &self.local_peer_id);
        let state = read_clock_state(
            self.content_store.as_ref(),
            self.location_index.as_ref(),
            &config,
            &self.local_peer_id,
        );

        let mut fields = vec![(
            entity_ecf::text("mode"),
            entity_ecf::text(&config.mode),
        )];

        if let Some(ts) = state.timestamp {
            fields.push((
                entity_ecf::text("timestamp"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(ts as i64),
                )]),
            ));
        }

        if let Some(counter) = state.logical {
            fields.push((
                entity_ecf::text("logical"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("counter"),
                    entity_ecf::integer(counter as i64),
                )]),
            ));
        }

        if let Some(ref entries) = state.vector {
            let entry_pairs: Vec<_> = entries
                .iter()
                .map(|(k, v)| (entity_ecf::text(k), entity_ecf::integer(*v as i64)))
                .collect();
            fields.push((
                entity_ecf::text("vector"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(entry_pairs),
                )]),
            ));
        }

        if let Some(ref hlc) = state.hlc {
            fields.push((
                entity_ecf::text("hlc"),
                entity_ecf::Value::Map(vec![
                    (
                        entity_ecf::text("logical"),
                        entity_ecf::integer(hlc.logical as i64),
                    ),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(hlc.peer.to_bytes().to_vec()),
                    ),
                    (
                        entity_ecf::text("physical"),
                        entity_ecf::integer(hlc.physical as i64),
                    ),
                ]),
            ));
        }

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(fields));
        let result = Entity::new("system/clock/state", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Clock state reading
// ---------------------------------------------------------------------------

struct ClockState {
    timestamp: Option<u64>,
    logical: Option<u64>,
    vector: Option<HashMap<String, u64>>,
    hlc: Option<HlcState>,
}

pub(crate) struct HlcState {
    pub(crate) physical: u64,
    pub(crate) logical: u64,
    pub(crate) peer: Hash,
}

fn read_clock_state(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    config: &ClockConfig,
    local_peer_id: &str,
) -> ClockState {
    let mut state = ClockState {
        timestamp: None,
        logical: None,
        vector: None,
        hlc: None,
    };

    // Include wall timestamp when mode is "wall" or wall_clock is true
    if config.mode == "wall" || config.wall_clock {
        state.timestamp = Some(system_clock_ms());
    }

    if config.mode == "logical" || config.mode == "vector" || config.mode == "hlc" {
        state.logical = Some(read_logical_counter(content_store, location_index, local_peer_id));
    }

    if config.mode == "vector" {
        state.vector = Some(read_vector_entries(content_store, location_index, local_peer_id));
    }

    if config.mode == "hlc" {
        state.hlc = Some(read_hlc_state(content_store, location_index, local_peer_id));
    }

    state
}

fn read_logical_counter(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> u64 {
    let path = format!("/{}/system/clock/logical", local_peer_id);
    let hash = match location_index.get(&path) {
        Some(h) => h,
        None => return 0,
    };
    let entity = match content_store.get(&hash) {
        Some(e) => e,
        None => return 0,
    };
    decode_counter(&entity.data).unwrap_or(0)
}

fn read_vector_entries(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> HashMap<String, u64> {
    let path = format!("/{}/system/clock/vector", local_peer_id);
    let hash = match location_index.get(&path) {
        Some(h) => h,
        None => return HashMap::new(),
    };
    let entity = match content_store.get(&hash) {
        Some(e) => e,
        None => return HashMap::new(),
    };
    decode_vector_entries(&entity.data).unwrap_or_default()
}

fn read_hlc_state(
    content_store: &dyn ContentStore,
    location_index: &dyn LocationIndex,
    local_peer_id: &str,
) -> HlcState {
    let path = format!("/{}/system/clock/hlc", local_peer_id);
    let hash = match location_index.get(&path) {
        Some(h) => h,
        None => {
            return HlcState {
                physical: system_clock_ms(),
                logical: 0,
                peer: Hash::zero(),
            };
        }
    };
    let entity = match content_store.get(&hash) {
        Some(e) => e,
        None => {
            return HlcState {
                physical: system_clock_ms(),
                logical: 0,
                peer: Hash::zero(),
            };
        }
    };
    decode_hlc(&entity.data).unwrap_or(HlcState {
        physical: system_clock_ms(),
        logical: 0,
        peer: Hash::zero(),
    })
}

// ---------------------------------------------------------------------------
// compare operation (§3.3)
// ---------------------------------------------------------------------------

impl ClockHandler {
    async fn handle_compare(&self, ctx: &HandlerContext) -> Result<HandlerResult, HandlerError> {
        tracing::debug!(request_id = %ctx.request_id, "clock: compare");
        let (a, b) = decode_compare_params(&ctx.params.data)?;
        let order = compare_clocks(&a, &b)?;

        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("order"),
            entity_ecf::text(order),
        )]));
        let result = Entity::new("system/clock/compare-result", data)
            .map_err(|e| HandlerError::Internal(e.to_string()))?;
        Ok(HandlerResult {
            status: STATUS_OK,
            result,
        included: std::collections::HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Clock value types for comparison
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum ClockValue {
    Timestamp { ms: u64 },
    Logical { counter: u64 },
    Vector { entries: HashMap<String, u64> },
    Hlc { physical: u64, logical: u64, peer: Hash },
}

fn detect_clock_type(val: &ciborium::Value) -> Result<ClockValue, HandlerError> {
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("clock value must be a map".into()))?;

    let mut has_ms = false;
    let mut has_counter = false;
    let mut has_entries = false;
    let mut has_physical = false;

    let mut ms = 0u64;
    let mut counter = 0u64;
    let mut entries = HashMap::new();
    let mut physical = 0u64;
    let mut logical = 0u64;
    let mut peer = Hash::zero();

    for (k, v) in map {
        match k.as_text() {
            Some("ms") => {
                has_ms = true;
                ms = v
                    .as_integer()
                    .map(|i| i128::from(i) as u64)
                    .unwrap_or(0);
            }
            Some("counter") => {
                has_counter = true;
                counter = v
                    .as_integer()
                    .map(|i| i128::from(i) as u64)
                    .unwrap_or(0);
            }
            Some("entries") => {
                has_entries = true;
                if let Some(m) = v.as_map() {
                    for (ek, ev) in m {
                        if let Some(key) = ek.as_text() {
                            let val = ev
                                .as_integer()
                                .map(|i| i128::from(i) as u64)
                                .unwrap_or(0);
                            entries.insert(key.to_string(), val);
                        }
                    }
                }
            }
            Some("physical") => {
                has_physical = true;
                physical = v
                    .as_integer()
                    .map(|i| i128::from(i) as u64)
                    .unwrap_or(0);
            }
            Some("logical") => {
                logical = v
                    .as_integer()
                    .map(|i| i128::from(i) as u64)
                    .unwrap_or(0);
            }
            Some("peer") => {
                if let ciborium::Value::Bytes(b) = v {
                    peer = Hash::from_bytes(b).unwrap_or(Hash::zero());
                }
            }
            _ => {}
        }
    }

    // Detect type based on which fields are present (§6.4)
    if has_physical {
        Ok(ClockValue::Hlc {
            physical,
            logical,
            peer,
        })
    } else if has_entries {
        Ok(ClockValue::Vector { entries })
    } else if has_counter {
        Ok(ClockValue::Logical { counter })
    } else if has_ms {
        Ok(ClockValue::Timestamp { ms })
    } else {
        Err(HandlerError::InvalidParams(
            "clock value has no recognizable fields".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Comparison algorithms (§6.4)
// ---------------------------------------------------------------------------

fn compare_clocks(a: &ClockValue, b: &ClockValue) -> Result<&'static str, HandlerError> {
    match (a, b) {
        (ClockValue::Timestamp { ms: a_ms }, ClockValue::Timestamp { ms: b_ms }) => {
            Ok(compare_timestamps(*a_ms, *b_ms))
        }
        (ClockValue::Logical { counter: a_c }, ClockValue::Logical { counter: b_c }) => {
            Ok(compare_logical(*a_c, *b_c))
        }
        (ClockValue::Vector { entries: a_e }, ClockValue::Vector { entries: b_e }) => {
            Ok(compare_vector(a_e, b_e))
        }
        (
            ClockValue::Hlc {
                physical: a_p,
                logical: a_l,
                peer: a_peer,
            },
            ClockValue::Hlc {
                physical: b_p,
                logical: b_l,
                peer: b_peer,
            },
        ) => Ok(compare_hlc(*a_p, *a_l, a_peer, *b_p, *b_l, b_peer)),
        _ => Err(HandlerError::InvalidParams(
            "a and b must be the same clock type".into(),
        )),
    }
}

/// §6.4.1 Timestamp comparison
fn compare_timestamps(a_ms: u64, b_ms: u64) -> &'static str {
    if a_ms < b_ms {
        "before"
    } else if a_ms > b_ms {
        "after"
    } else {
        "equal"
    }
}

/// §6.4.2 Logical clock comparison
fn compare_logical(a_counter: u64, b_counter: u64) -> &'static str {
    if a_counter < b_counter {
        "before"
    } else if a_counter > b_counter {
        "after"
    } else {
        "equal"
    }
}

/// §6.4.3 Vector clock comparison — partial order with concurrency detection
fn compare_vector(a: &HashMap<String, u64>, b: &HashMap<String, u64>) -> &'static str {
    let mut a_leq_b = true;
    let mut b_leq_a = true;

    // Collect all peer IDs from both vectors
    let mut all_peers: Vec<&String> = a.keys().collect();
    for k in b.keys() {
        if !a.contains_key(k) {
            all_peers.push(k);
        }
    }

    for peer_id in &all_peers {
        let a_val = a.get(*peer_id).copied().unwrap_or(0);
        let b_val = b.get(*peer_id).copied().unwrap_or(0);
        if a_val > b_val {
            a_leq_b = false;
        }
        if b_val > a_val {
            b_leq_a = false;
        }
    }

    if a_leq_b && b_leq_a {
        "equal"
    } else if a_leq_b {
        "before"
    } else if b_leq_a {
        "after"
    } else {
        "concurrent"
    }
}

/// §6.4.4 HLC comparison — total order (physical → logical → peer tiebreak)
fn compare_hlc(
    a_physical: u64,
    a_logical: u64,
    a_peer: &Hash,
    b_physical: u64,
    b_logical: u64,
    b_peer: &Hash,
) -> &'static str {
    if a_physical < b_physical {
        return "before";
    }
    if a_physical > b_physical {
        return "after";
    }
    if a_logical < b_logical {
        return "before";
    }
    if a_logical > b_logical {
        return "after";
    }
    if a_peer < b_peer {
        return "before";
    }
    if a_peer > b_peer {
        return "after";
    }
    "equal"
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_compare_params(
    params_data: &[u8],
) -> Result<(ClockValue, ClockValue), HandlerError> {
    let val: ciborium::Value = ciborium::from_reader(params_data)
        .map_err(|e| HandlerError::InvalidParams(format!("decode params: {}", e)))?;
    let map = val
        .as_map()
        .ok_or_else(|| HandlerError::InvalidParams("params not a map".into()))?;

    let mut a_val = None;
    let mut b_val = None;

    for (k, v) in map {
        match k.as_text() {
            Some("a") => a_val = Some(v),
            Some("b") => b_val = Some(v),
            _ => {}
        }
    }

    let a = a_val.ok_or_else(|| HandlerError::InvalidParams("missing field 'a'".into()))?;
    let b = b_val.ok_or_else(|| HandlerError::InvalidParams("missing field 'b'".into()))?;

    let a_clock = detect_clock_type(a)?;
    let b_clock = detect_clock_type(b)?;

    Ok((a_clock, b_clock))
}

pub(crate) fn decode_counter(data: &[u8]) -> Option<u64> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("counter") {
            return v.as_integer().map(|i| i128::from(i) as u64);
        }
    }
    None
}

pub(crate) fn decode_vector_entries(data: &[u8]) -> Option<HashMap<String, u64>> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    for (k, v) in map {
        if k.as_text() == Some("entries") {
            let entries_map = v.as_map()?;
            let mut result = HashMap::new();
            for (ek, ev) in entries_map {
                if let Some(key) = ek.as_text() {
                    let val = ev.as_integer().map(|i| i128::from(i) as u64).unwrap_or(0);
                    result.insert(key.to_string(), val);
                }
            }
            return Some(result);
        }
    }
    None
}

pub(crate) fn decode_hlc(data: &[u8]) -> Option<HlcState> {
    let val: ciborium::Value = ciborium::from_reader(data).ok()?;
    let map = val.as_map()?;
    let mut physical = 0u64;
    let mut logical = 0u64;
    let mut peer = Hash::zero();

    for (k, v) in map {
        match k.as_text() {
            Some("physical") => {
                physical = v.as_integer().map(|i| i128::from(i) as u64).unwrap_or(0);
            }
            Some("logical") => {
                logical = v.as_integer().map(|i| i128::from(i) as u64).unwrap_or(0);
            }
            Some("peer") => {
                if let ciborium::Value::Bytes(b) = v {
                    peer = Hash::from_bytes(b).unwrap_or(Hash::zero());
                }
            }
            _ => {}
        }
    }

    Some(HlcState {
        physical,
        logical,
        peer,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Wall clock milliseconds since Unix epoch (§2.1).
pub fn system_clock_ms() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn error_result(status: u32, code: &str, message: &str) -> HandlerResult {
    let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
        (entity_ecf::text("code"), entity_ecf::text(code)),
        (entity_ecf::text("message"), entity_ecf::text(message)),
    ]));
    // Canonical error type per ENTITY-NATIVE-TYPE-SYSTEM — matches Go's
    // TypeError so cross-impl SDKs read {code,message} from the entity
    // instead of falling back to status-default codes.
    let result = Entity::new("system/protocol/error", data).unwrap();
    HandlerResult { status, result, included: std::collections::HashMap::new() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use entity_store::{MemoryContentStore, MemoryLocationIndex};

    fn test_peer_id() -> String {
        "peer1abc".to_string()
    }

    fn make_handler() -> ClockHandler {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        ClockHandler::new(store, index, test_peer_id())
    }

    fn make_handler_with_stores() -> (ClockHandler, Arc<dyn ContentStore>, Arc<dyn LocationIndex>) {
        let store: Arc<dyn ContentStore> = Arc::new(MemoryContentStore::new());
        let index: Arc<dyn LocationIndex> = Arc::new(MemoryLocationIndex::new());
        let handler = ClockHandler::new(store.clone(), index.clone(), test_peer_id());
        (handler, store, index)
    }

    fn make_ctx(operation: &str, params_data: entity_ecf::Value) -> HandlerContext {
        let params = Entity::new(
            "system/clock/compare-params",
            entity_ecf::to_ecf(&params_data),
        )
        .unwrap();
        let execute = Entity::new(
            entity_types::TYPE_EXECUTE,
            entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
                entity_ecf::text("request_id"),
                entity_ecf::text("r1"),
            )])),
        )
        .unwrap();
        HandlerContext {
            handler_grant: None,
            caller_capability: None,
            execute,
            params,
            pattern: format!("/{}/system/clock", test_peer_id()),
            suffix: String::new(),
            resource_target: None,
            author: None,
            session_peer_id: None,
            request_id: "r1".to_string(),
            operation: operation.to_string(),
            execute_fn: None,
            included: HashMap::new(),
            matching_grant: None,
            capability_hash: None,
            handler_grant_hash: None,
            bounds: None,
            is_external: false,
        }
    }

    fn store_config(
        store: &Arc<dyn ContentStore>,
        index: &Arc<dyn LocationIndex>,
        mode: &str,
        wall_clock: bool,
    ) {
        let peer_id = test_peer_id();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (entity_ecf::text("mode"), entity_ecf::text(mode)),
            (
                entity_ecf::text("wall_clock"),
                entity_ecf::bool_val(wall_clock),
            ),
        ]));
        let path = format!("/{}/system/clock/config", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);
    }

    fn store_logical(
        store: &Arc<dyn ContentStore>,
        index: &Arc<dyn LocationIndex>,
        counter: u64,
    ) {
        let peer_id = test_peer_id();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("counter"),
            entity_ecf::integer(counter as i64),
        )]));
        let path = format!("/{}/system/clock/logical", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);
    }

    fn store_vector(
        store: &Arc<dyn ContentStore>,
        index: &Arc<dyn LocationIndex>,
        entries: &[(&str, u64)],
    ) {
        let peer_id = test_peer_id();
        let entry_pairs: Vec<_> = entries
            .iter()
            .map(|(k, v)| (entity_ecf::text(*k), entity_ecf::integer(*v as i64)))
            .collect();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![(
            entity_ecf::text("entries"),
            entity_ecf::Value::Map(entry_pairs),
        )]));
        let path = format!("/{}/system/clock/vector", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);
    }

    fn store_hlc(
        store: &Arc<dyn ContentStore>,
        index: &Arc<dyn LocationIndex>,
        physical: u64,
        logical: u64,
        peer: Hash,
    ) {
        let peer_id = test_peer_id();
        let data = entity_ecf::to_ecf(&entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("logical"),
                entity_ecf::integer(logical as i64),
            ),
            (
                entity_ecf::text("peer"),
                entity_ecf::Value::Bytes(peer.to_bytes().to_vec()),
            ),
            (
                entity_ecf::text("physical"),
                entity_ecf::integer(physical as i64),
            ),
        ]));
        let path = format!("/{}/system/clock/hlc", peer_id);
        let entity = Entity::new(&path, data).unwrap();
        let hash = store.put(entity).unwrap();
        index.set(&path, hash);
    }

    // --- Handler metadata ---

    #[test]
    fn test_pattern() {
        let handler = make_handler();
        assert_eq!(handler.pattern(), format!("/{}/system/clock", test_peer_id()));
        assert_eq!(handler.name(), "clock");
        assert_eq!(handler.operations(), &["now", "compare", "tick"]);
    }

    // --- now operation ---

    #[tokio::test]
    async fn test_now_wall_mode() {
        let handler = make_handler();
        let ctx = make_ctx("now", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        assert_eq!(result.result.entity_type, "system/clock/state");

        // Decode and check fields
        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        let mode = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("mode"))
            .unwrap()
            .1
            .as_text()
            .unwrap();
        assert_eq!(mode, "wall");
        // Should have timestamp
        let ts = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("timestamp"))
            .unwrap();
        let ts_map = ts.1.as_map().unwrap();
        let ms = ts_map
            .iter()
            .find(|(k, _)| k.as_text() == Some("ms"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        assert!(i128::from(ms) > 0);
    }

    #[tokio::test]
    async fn test_now_logical_mode() {
        let (handler, store, index) = make_handler_with_stores();
        store_config(&store, &index, "logical", true);
        store_logical(&store, &index, 42);

        let ctx = make_ctx("now", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();

        // Should have logical
        let logical = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("logical"))
            .unwrap();
        let logical_map = logical.1.as_map().unwrap();
        let counter = logical_map
            .iter()
            .find(|(k, _)| k.as_text() == Some("counter"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        assert_eq!(i128::from(counter), 42);

        // Should also have timestamp (wall_clock=true)
        assert!(map.iter().any(|(k, _)| k.as_text() == Some("timestamp")));
    }

    #[tokio::test]
    async fn test_now_vector_mode() {
        let (handler, store, index) = make_handler_with_stores();
        store_config(&store, &index, "vector", true);
        store_logical(&store, &index, 5);
        store_vector(&store, &index, &[("peerA", 5), ("peerB", 3)]);

        let ctx = make_ctx("now", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();

        // Should have vector
        let vector = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("vector"))
            .unwrap();
        let vector_map = vector.1.as_map().unwrap();
        let entries = vector_map
            .iter()
            .find(|(k, _)| k.as_text() == Some("entries"))
            .unwrap();
        let entries_map = entries.1.as_map().unwrap();
        assert_eq!(entries_map.len(), 2);

        // Should have logical
        assert!(map.iter().any(|(k, _)| k.as_text() == Some("logical")));
    }

    #[tokio::test]
    async fn test_now_hlc_mode() {
        let (handler, store, index) = make_handler_with_stores();
        let peer_hash = Hash::compute("test", b"peer1");
        store_config(&store, &index, "hlc", true);
        store_logical(&store, &index, 10);
        store_hlc(&store, &index, 1709000000000, 3, peer_hash);

        let ctx = make_ctx("now", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);

        let val: ciborium::Value =
            ciborium::from_reader(result.result.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();

        // Should have hlc
        let hlc = map
            .iter()
            .find(|(k, _)| k.as_text() == Some("hlc"))
            .unwrap();
        let hlc_map = hlc.1.as_map().unwrap();
        let physical = hlc_map
            .iter()
            .find(|(k, _)| k.as_text() == Some("physical"))
            .unwrap()
            .1
            .as_integer()
            .unwrap();
        assert_eq!(i128::from(physical), 1709000000000);

        // Should have logical
        assert!(map.iter().any(|(k, _)| k.as_text() == Some("logical")));
    }

    // --- compare operation ---

    #[tokio::test]
    async fn test_compare_timestamps() {
        let handler = make_handler();
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(1000),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(2000),
                )]),
            ),
        ]);
        let ctx = make_ctx("compare", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_OK);
        let order = extract_order(&result.result);
        assert_eq!(order, "before");

        // Equal
        let params_eq = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(5000),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(5000),
                )]),
            ),
        ]);
        let ctx_eq = make_ctx("compare", params_eq);
        let result_eq = handler.handle(&ctx_eq).await.unwrap();
        assert_eq!(extract_order(&result_eq.result), "equal");

        // After
        let params_after = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(3000),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(1000),
                )]),
            ),
        ]);
        let ctx_after = make_ctx("compare", params_after);
        let result_after = handler.handle(&ctx_after).await.unwrap();
        assert_eq!(extract_order(&result_after.result), "after");
    }

    #[tokio::test]
    async fn test_compare_logical() {
        let handler = make_handler();
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("counter"),
                    entity_ecf::integer(5),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("counter"),
                    entity_ecf::integer(10),
                )]),
            ),
        ]);
        let ctx = make_ctx("compare", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(extract_order(&result.result), "before");
    }

    #[tokio::test]
    async fn test_compare_vector() {
        let handler = make_handler();

        // a < b (a before b)
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(1)),
                        (entity_ecf::text("p2"), entity_ecf::integer(2)),
                    ]),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(2)),
                        (entity_ecf::text("p2"), entity_ecf::integer(3)),
                    ]),
                )]),
            ),
        ]);
        let ctx = make_ctx("compare", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(extract_order(&result.result), "before");

        // Concurrent (some entries higher in each)
        let params_conc = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(3)),
                        (entity_ecf::text("p2"), entity_ecf::integer(1)),
                    ]),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(1)),
                        (entity_ecf::text("p2"), entity_ecf::integer(3)),
                    ]),
                )]),
            ),
        ]);
        let ctx_conc = make_ctx("compare", params_conc);
        let result_conc = handler.handle(&ctx_conc).await.unwrap();
        assert_eq!(extract_order(&result_conc.result), "concurrent");

        // Equal
        let params_eq = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(2)),
                    ]),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("entries"),
                    entity_ecf::Value::Map(vec![
                        (entity_ecf::text("p1"), entity_ecf::integer(2)),
                    ]),
                )]),
            ),
        ]);
        let ctx_eq = make_ctx("compare", params_eq);
        let result_eq = handler.handle(&ctx_eq).await.unwrap();
        assert_eq!(extract_order(&result_eq.result), "equal");
    }

    #[tokio::test]
    async fn test_compare_hlc() {
        let handler = make_handler();
        let peer_a = Hash::compute("test", b"peerA");
        let peer_b = Hash::compute("test", b"peerB");

        // Different physical times
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(0)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_a.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(1000)),
                ]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(0)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_b.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(2000)),
                ]),
            ),
        ]);
        let ctx = make_ctx("compare", params);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(extract_order(&result.result), "before");

        // Same physical, different logical
        let params2 = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(5)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_a.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(1000)),
                ]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(3)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_b.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(1000)),
                ]),
            ),
        ]);
        let ctx2 = make_ctx("compare", params2);
        let result2 = handler.handle(&ctx2).await.unwrap();
        assert_eq!(extract_order(&result2.result), "after");

        // Same physical and logical, peer tiebreak
        let params3 = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(1)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_a.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(1000)),
                ]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![
                    (entity_ecf::text("logical"), entity_ecf::integer(1)),
                    (
                        entity_ecf::text("peer"),
                        entity_ecf::Value::Bytes(peer_a.to_bytes().to_vec()),
                    ),
                    (entity_ecf::text("physical"), entity_ecf::integer(1000)),
                ]),
            ),
        ]);
        let ctx3 = make_ctx("compare", params3);
        let result3 = handler.handle(&ctx3).await.unwrap();
        assert_eq!(extract_order(&result3.result), "equal");
    }

    // --- Unknown operation ---

    #[tokio::test]
    async fn test_unknown_operation() {
        let handler = make_handler();
        let ctx = make_ctx("invalid", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_tick_not_implemented() {
        let handler = make_handler();
        let ctx = make_ctx("tick", entity_ecf::Value::Null);
        let result = handler.handle(&ctx).await.unwrap();
        assert_eq!(result.status, STATUS_NOT_SUPPORTED);
    }

    // --- Compare type mismatch ---

    #[tokio::test]
    async fn test_compare_type_mismatch() {
        let handler = make_handler();
        let params = entity_ecf::Value::Map(vec![
            (
                entity_ecf::text("a"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("ms"),
                    entity_ecf::integer(1000),
                )]),
            ),
            (
                entity_ecf::text("b"),
                entity_ecf::Value::Map(vec![(
                    entity_ecf::text("counter"),
                    entity_ecf::integer(5),
                )]),
            ),
        ]);
        let ctx = make_ctx("compare", params);
        let result = handler.handle(&ctx).await;
        assert!(result.is_err());
    }

    // --- Helpers ---

    fn extract_order(entity: &Entity) -> String {
        let val: ciborium::Value =
            ciborium::from_reader(entity.data.as_slice()).unwrap();
        let map = val.as_map().unwrap();
        for (k, v) in map {
            if k.as_text() == Some("order") {
                return v.as_text().unwrap().to_string();
            }
        }
        panic!("no order field found");
    }
}
