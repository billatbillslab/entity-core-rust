//! V7.67 Phase 1 cohort cross-impl byte-equality lock-gate (Rust side).
//!
//! Per IMPL-TEAM-ALIGNMENT-V7.67 §3.4, the Phase 1 lock-gate is per-impl
//! byte-equal Ed448 sign/verify + content-hash + SHA-384 on a corpus-pinned
//! seed. This test runs the placeholder pin from the Go cohort's
//! V7.67 Phase 1 cross-impl pin
//! and asserts byte-equality against Go's §3 expected outputs. A green run
//! proves ed448-goldilocks ↔ CIRCL agree and ECF/SHA-256/SHA-384 converge.
//!
//! Pin: Ed448 seed = 0x42 × 57; message = "v7.67 Phase 1 cohort cross-impl
//! Ed448 fixture"; SHA-384 fixture inherits v7.66 0xAA × 64.
//!
//! When architecture publishes core-protocol-domain/specs/test-vectors/v767/,
//! swap SEED + the Go-expected constants for the corpus-pinned values and
//! re-run. The peer_canon_v7_67_phase1 suite asserts determinism + structure;
//! this suite asserts cross-impl byte convergence — they are complementary.

use entity_crypto::{
    peer_identity_hash_with_key_type, peer_entity_from_components_with_key_type, Ed448Keypair,
    KeyType, ED448_SECRET_KEY_LEN,
};
use entity_hash::{Hash, HASH_ALGORITHM_SHA384};

const SEED: [u8; ED448_SECRET_KEY_LEN] = [0x42; ED448_SECRET_KEY_LEN];
const MSG: &[u8] = b"v7.67 Phase 1 cohort cross-impl Ed448 fixture";
const FIXTURE_PUBKEY: [u8; 64] = [0xAA; 64];

// Go-side expected outputs (§3 of the cohort pin doc).
const GO_PUBLIC_KEY: &str = "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00";
const GO_PEER_ID: &str = "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4";
const GO_SIGNATURE: &str = "0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400";
const GO_PEER_CONTENT_HASH: &str = "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748";
const GO_SHA384_DIGEST: &str = "2e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01c059c1ed5775824bcffc50df0f3eef5a69";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn cohort_byte_compare_against_go() {
    let kp = Ed448Keypair::from_seed(&SEED).expect("seed accepted");

    // 1. public_key (57 B)
    let pk = kp.public_key_bytes();
    let pk_hex = hex(&pk);
    println!("public_key   = {pk_hex}");

    // 2. peer_id (Base58, canonical 0x02/0x01)
    let peer_id = kp.peer_id();
    let pid = peer_id.as_str().to_string();
    println!("peer_id      = {pid}");

    // 3. signature (114 B)
    let sig = kp.sign(MSG);
    let sig_hex = hex(&sig);
    println!("signature    = {sig_hex}");

    // 4. system/peer content_hash (33 B, SHA-256)
    let ch = peer_identity_hash_with_key_type(&pk, KeyType::Ed448).expect("hash");
    let ch_hex = hex(&ch.to_bytes());
    println!("content_hash = {ch_hex}");

    // 5. SHA-384 digest (48 B) over the v7.66 0xAA × 64 fixture
    let fx = peer_entity_from_components_with_key_type(&FIXTURE_PUBKEY, KeyType::ExperimentalTest)
        .expect("fixture entity");
    let sha384 = Hash::compute_format(&fx.entity_type, &fx.data, HASH_ALGORITHM_SHA384).unwrap();
    let sha384_hex = hex(sha384.digest());
    println!("sha384       = {sha384_hex}");
    println!("ecf_len      = {}", fx.data.len());

    // Byte-equality assertions against Go.
    assert_eq!(pk_hex, GO_PUBLIC_KEY, "public_key mismatch");
    assert_eq!(pid, GO_PEER_ID, "peer_id mismatch");
    assert_eq!(sig_hex, GO_SIGNATURE, "signature mismatch");
    assert_eq!(ch_hex, GO_PEER_CONTENT_HASH, "peer content_hash mismatch");
    assert_eq!(sha384_hex, GO_SHA384_DIGEST, "sha384 digest mismatch");
}
