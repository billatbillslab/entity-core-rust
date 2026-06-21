//! Bootstrap + IdentityBundle helpers — Dictionary mapping for
//! BootstrapResult / BootstrapStatus / IdentityBundle round-tripping.
//! Used by the bootstrap + bundle `#[func]`s in `peer_node.rs`.

use godot::prelude::*;

use entity_sdk::identity_bootstrap::{BootstrapResult, BootstrapStatus};

/// Convert a `BootstrapResult` into a GDScript Dictionary.
///
/// Shape:
///   AlreadyBootstrapped → { status: "already_bootstrapped",
///                           identity_hash, quorum_id }
///   Bootstrapped → { status: "bootstrapped", identity_hash,
///                    quorum_id, controller_cert, peer_config_path,
///                    issued_caps: [PackedByteArray] }
pub(crate) fn bootstrap_result_to_variant(r: BootstrapResult) -> Variant {
    let mut dict = Dictionary::new();
    match r {
        BootstrapResult::AlreadyBootstrapped {
            identity_hash,
            quorum_id,
        } => {
            dict.set("status", "already_bootstrapped");
            dict.set("identity_hash", hash_to_pba(&identity_hash));
            dict.set("quorum_id", hash_to_pba(&quorum_id));
        }
        BootstrapResult::Bootstrapped {
            identity_hash,
            quorum_id,
            controller_cert,
            peer_config_path,
            issued_caps,
        } => {
            dict.set("status", "bootstrapped");
            dict.set("identity_hash", hash_to_pba(&identity_hash));
            dict.set("quorum_id", hash_to_pba(&quorum_id));
            dict.set("controller_cert", hash_to_pba(&controller_cert));
            dict.set("peer_config_path", GString::from(peer_config_path.as_str()));
            let mut caps = VariantArray::new();
            for cap in issued_caps {
                caps.push(&hash_to_pba(&cap).to_variant());
            }
            dict.set("issued_caps", caps);
        }
    }
    dict.to_variant()
}

/// Convert a `BootstrapStatus` into a GDScript Dictionary.
///
/// Shape: { bootstrapped: bool, identity_hash: PBA,
///          quorum_id: PBA|null, peer_config_path: String|null }
pub(crate) fn bootstrap_status_to_dict(s: BootstrapStatus) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.set("bootstrapped", s.bootstrapped);
    dict.set("identity_hash", hash_to_pba(&s.identity_hash));
    match s.quorum_id {
        Some(h) => dict.set("quorum_id", hash_to_pba(&h)),
        None => dict.set("quorum_id", Variant::nil()),
    }
    match s.peer_config_path {
        Some(p) => dict.set("peer_config_path", GString::from(p.as_str())),
        None => dict.set("peer_config_path", Variant::nil()),
    }
    dict
}

fn hash_to_pba(h: &entity_hash::Hash) -> PackedByteArray {
    let mut pba = PackedByteArray::new();
    pba.extend(h.to_bytes().to_vec());
    pba
}

/// Decode a GDScript Dictionary of properties into the SDK's typed
/// `Vec<(String, ciborium::Value)>` shape. String keys only; non-
/// string keys are skipped with a `godot_warn!`. Values map per:
/// - Bool → ciborium::Value::Bool
/// - Int → ciborium::Value::Integer
/// - Float → ciborium::Value::Float
/// - String → ciborium::Value::Text
/// - PackedByteArray → ciborium::Value::Bytes
/// - other → skipped with a `godot_warn!`
///
/// The bootstrap SDK injects `kind`, `function`, `mode` itself; per
/// the SDK docs callers SHOULD NOT include those three keys.
pub(crate) fn decode_string_properties(
    dict: &VarDictionary,
) -> Vec<(String, ciborium::Value)> {
    use ciborium::Value;
    let mut out: Vec<(String, Value)> = Vec::new();
    for (k, v) in dict.iter_shared() {
        let Ok(key_s) = k.try_to::<GString>() else {
            godot_warn!("bootstrap properties: skipping non-string key");
            continue;
        };
        let key = key_s.to_string();
        let value = match v.get_type() {
            VariantType::BOOL => Value::Bool(v.to::<bool>()),
            VariantType::INT => {
                Value::Integer(ciborium::value::Integer::from(v.to::<i64>()))
            }
            VariantType::FLOAT => Value::Float(v.to::<f64>()),
            VariantType::STRING => Value::Text(v.to::<GString>().to_string()),
            VariantType::PACKED_BYTE_ARRAY => {
                Value::Bytes(v.to::<PackedByteArray>().to_vec())
            }
            other => {
                godot_warn!(
                    "bootstrap properties: skipping key {:?} — unsupported value type {:?}",
                    key,
                    other
                );
                continue;
            }
        };
        out.push((key, value));
    }
    out
}
