//! V7.67 Phase 2 matrix-vector cohort cross-impl byte-equality lock-gate
//! (Rust side).
//!
//! Mirrors `entity-core-go/cmd/v767-phase2-pins/main.go`: derives the
//! `MATRIX-M2` / `MATRIX-M3` / `MATRIX-M6` tuples from the ratified seeds in
//! `core-protocol-domain/specs/test-vectors/v767/SEEDS.md` §2 and runs the
//! seven §7 cross-impl byte-equality gates against the Go cohort's pins.
//!
//! Per SEEDS.md §5 step 3 / §7, Rust regression-confirms Phase 1 byte-equal
//! (see `cohort_compare_v767_phase1`) and runs Phase 2 with the §2.1 seeds.
//! The seven §7 gates per vector: pubkey, peer_id, peer.data CBOR, home-format
//! content_hash, cap-token CBOR, active-format cap-token content_hash, and A's
//! signature over the cap-token content_hash.
//!
//! ## §7-gate-5 empty-scope — RULED, 3-way green (Rust was spec-correct)
//!
//! All seven gates now converge byte-for-byte across Go (post-fix `3cfb353`),
//! Rust (`d38d1f8`), and Python (`a2463be`) on all three vectors; the folded
//! pins below ARE the arch-ratified values
//! (`v767/conformance-vectors-v1.diag`, `.cbor` regenerated at F16 close).
//!
//! The round-trip first surfaced as a gates-5–7 divergence (cap-token CBOR →
//! content_hash → signature), isolated to one cause repeated across M2/M3/M6:
//! the `GrantEntry`'s two unconstrained scope dimensions (`handlers.include`,
//! `operations.include`).
//!
//! - Rust emits the empty scope as `{include: []}` → `a1 67696e636c756465 80`.
//! - Go originally emitted `{include: null}` → `a1 67696e636c756465 f6`.
//!
//! `include` is a `list_of: pattern` field; an unconstrained dimension is a
//! ZERO-ELEMENT LIST. The locked v1 ECF corpus pins these as DISTINCT canonical
//! forms — `length.1` empty array → `h'80'`, `primitive.1` null → `h'f6'`
//! (`ecf-conformance/conformance-vectors-v1.diag`). Go's `f6` was a
//! `[]string(nil) → CBOR null` serialization artifact of its `GrantEntry`, NOT
//! a spec mandate; fixed at `core/types/system.go::CapabilityScope.MarshalCBOR`
//! (`3cfb353`). Architecture RULED Rust's `0x80` form (no spec change — both
//! halves bound by existing normative text: ENTITY-CBOR-ENCODING §232 forbids
//! field drop, V7 §3.6 `list_of(pattern)` typing excludes `null`):
//! the architecture ruling on empty-scope `include`. The cap-layer constants
//! below are that ruled `0x80` form; the peer-layer constants (gates 1–4) are
//! the cohort's verbatim shared pins.
//!
//! This stayed latent because handshake caps are each self-signed by the
//! minting peer and verified against received bytes (never re-encoded
//! cross-impl); the byte-pin round-trip is the first surface that forces
//! independent re-derivation. Trail: `docs/SPEC-AMBIGUITIES.md` (RULED).
//!
//! Derivation (SEEDS.md §2.3/§2.4/§2.5):
//!   - each peer's `system/peer` entity is authored under its HOME format
//!     (M3-A / M6-A = SHA-384; all others SHA-256); content_hash is read off
//!     that entity (v7.69 §1.8 — identity references use the identity's home
//!     format)
//!   - cap-token: grants=[{resources.include=["system/validate/matrix/*"]}],
//!     granter = SingleSig(A home content_hash), grantee = B home content_hash,
//!     parent=null, created_at=0, expires_at=0
//!   - the cap-token ENTITY is authored under the ACTIVE negotiated format
//!     (SHA-256 in all three vectors per SEEDS.md §2.2)
//!   - A signs the cap-token's full 33-byte wire content_hash (RFC 8032
//!     deterministic → byte-equal cross-library)

use entity_capability::{CapabilityToken, GrantEntry, Granter, IdScope, PathScope};
use entity_crypto::{
    peer_entity_from_components_with_format, Ed448Keypair, Keypair, KeyType,
    ED448_SECRET_KEY_LEN,
};
use entity_hash::{Hash, HASH_ALGORITHM_SHA256, HASH_ALGORITHM_SHA384};
use entity_types::TYPE_CAP_TOKEN;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// One peer's derived pins: (peer.data CBOR hex, full-wire content_hash bytes).
struct PeerPin {
    data_cbor_hex: String,
    content_hash: Hash,
}

/// Derive a peer's `system/peer` entity under its home format and read off the
/// data CBOR + content_hash (SEEDS.md §2.4 home-format reference discipline).
fn derive_peer_pin(public_key: &[u8], key_type: KeyType, home_format: u8) -> PeerPin {
    let ent = peer_entity_from_components_with_format(public_key, key_type, home_format)
        .expect("peer entity");
    PeerPin {
        data_cbor_hex: hex(&ent.data),
        content_hash: ent.content_hash,
    }
}

/// Build the SEEDS.md §2.3 root cap-token, author it under the active format,
/// and return (cap-token data CBOR hex, active-format content_hash bytes).
fn build_root_cap(granter_home: &Hash, grantee_home: &Hash, active_format: u8) -> (String, Hash) {
    let token = CapabilityToken {
        grants: vec![GrantEntry {
            handlers: PathScope::new(vec![]),
            resources: PathScope::new(vec!["system/validate/matrix/*".into()]),
            operations: IdScope::new(vec![]),
            peers: None,
            constraints: None,
            allowances: None,
        }],
        granter: Granter::single(*granter_home),
        grantee: *grantee_home,
        parent: None,
        created_at: 0,
        expires_at: Some(0),
        not_before: None,
        delegation_caveats: None,
    };
    let entity = token
        .to_entity_with_format(active_format)
        .expect("cap-token entity");
    assert_eq!(entity.entity_type, TYPE_CAP_TOKEN);
    (hex(&entity.data), entity.content_hash)
}

// Peer-layer constants (gates 1–4) are the cohort's shared pins. Cap-layer
// constants (`*_CAP_*`, gates 5–7) are the arch-ratified `0x80` empty-scope
// form (per the empty-scope `include` ruling) — now byte-equal across all
// three impls after Go's `3cfb353` fix folded into the v767 `.diag`/`.cbor`.

// === MATRIX-M2: cross-key, same-hash (Ed448/SHA-256 ↔ Ed25519/SHA-256) ===
// Go pins: V7.67 Phase 2 byte-pins cohort doc §3.
const M2_A_PUBKEY: &str = "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00";
const M2_A_PEER_ID: &str = "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4";
const M2_A_PEER_CBOR: &str = "a2686b65795f747970656565643434386a7075626c69635f6b657958392601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00";
const M2_A_CONTENT_HASH: &str = "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748";
const M2_B_PUBKEY: &str = "22fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6";
const M2_B_PEER_ID: &str = "2K68ekpdm3sTCUfTs39tpNxowivTsXpRsukodvtqwZmudX";
const M2_B_PEER_CBOR: &str = "a2686b65795f7479706567656432353531396a7075626c69635f6b6579582022fc297792f0b6ffc0bfcfdb7edb0c0aa14e025a365ec0e342e86e3829cb74b6";
const M2_B_CONTENT_HASH: &str = "00f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b";
const M2_CAP_CBOR: &str = "a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b676772616e7465725821002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c707486a637265617465645f6174006a657870697265735f617400";
const M2_CAP_CONTENT_HASH: &str = "0095852ce2ad1fa6ec97cf827413a328a1ca531a37984952a0f5f215c305b6e2ba";
const M2_CAP_SIG: &str = "6104711f3ba43ade204001ca3146c154b825b0db45a6be6811735bcbbc75da4e2cf5c6a69efb9d3bae3503b21164fd75e5b74f635c74f14f007381e23af338cb98afc299d45406956a029fb1bbfd418eff85ef2908467a56e549f4dbc74d50ca344ff0c1142770df68f956eccc3a5e023200";

// === MATRIX-M3: cross-hash, same-key (Ed25519). A home SHA-384, B home SHA-256. ===
const M3_A_PUBKEY: &str = "d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";
const M3_A_PEER_ID: &str = "2KJGifeh6LynPNnmyQqHrugjm7iW8YPQ4VpWSGgYvHp2VM";
const M3_A_PEER_CBOR: &str = "a2686b65795f7479706567656432353531396a7075626c69635f6b65795820d759793bbc13a2819a827c76adb6fba8a49aee007f49f2d0992d99b825ad2c48";
const M3_A_CONTENT_HASH: &str = "0166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c59";
const M3_B_PUBKEY: &str = "6355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56";
const M3_B_PEER_ID: &str = "2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5";
const M3_B_PEER_CBOR: &str = "a2686b65795f7479706567656432353531396a7075626c69635f6b657958206355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56";
const M3_B_CONTENT_HASH: &str = "00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040";
const M3_CAP_CBOR: &str = "a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e746565582100bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040676772616e74657258310166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c596a637265617465645f6174006a657870697265735f617400";
const M3_CAP_CONTENT_HASH: &str = "0053016041ab2f1b3826175cb8e6576d166969315beaed249e071abeb5e1808cbe";
const M3_CAP_SIG: &str = "05a6170bbf1eb188ee7423c7f989f5da668b043eb3d1d3a20c389979549931053d64fa56d3cbd0d35fbe0161c72b3044b485882bd1716e5d667b56a369b36100";

// === MATRIX-M6: combined cross-key + cross-hash. A Ed448 home SHA-384, B Ed25519 home SHA-256. ===
const M6_A_PUBKEY: &str = "ac3699dd5c3fb9461bf18ae2f943b129aa60d388ceb40be0b33cc1c37083faf2ed062cc7727376eae9afbdc66f433830abd5d93b64c0874780";
const M6_A_PEER_ID: &str = "3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD";
const M6_A_PEER_CBOR: &str = "a2686b65795f747970656565643434386a7075626c69635f6b65795839ac3699dd5c3fb9461bf18ae2f943b129aa60d388ceb40be0b33cc1c37083faf2ed062cc7727376eae9afbdc66f433830abd5d93b64c0874780";
const M6_A_CONTENT_HASH: &str = "01ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd";
const M6_B_PUBKEY: &str = "e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351";
const M6_B_PEER_ID: &str = "2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye";
const M6_B_PEER_CBOR: &str = "a2686b65795f7479706567656432353531396a7075626c69635f6b65795820e28a8970753332bd72fef413e6b0b2ef1b4aadda7aa2c141f233712a6876b351";
const M6_B_CONTENT_HASH: &str = "0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335";
const M6_CAP_CBOR: &str = "a5666772616e747381a36868616e646c657273a167696e636c75646580697265736f7572636573a167696e636c75646581781873797374656d2f76616c69646174652f6d61747269782f2a6a6f7065726174696f6e73a167696e636c75646580676772616e74656558210056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335676772616e746572583101ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd6a637265617465645f6174006a657870697265735f617400";
const M6_CAP_CONTENT_HASH: &str = "004ae3ec9d8999658ab164d454de81399bac3752fb3a7465120fe933621a41eab8";
const M6_CAP_SIG: &str = "547e8bf136b104228b1bb551e143e85a8585562b8b0a4a1791688cc3778ee41d7ebe305d5e5f387262dac8a7c722260affeb9bd42f1b707c8042b2aab14f73996f153e00c05b0243fad15121b0ec70f5d160f553979f332b5b6b392ef0617d2e345998b44c8503168d6cc584687759482d00";

fn assert_peer(
    tag: &str,
    pin: &PeerPin,
    pub_hex: &str,
    pub_want: &str,
    peer_id: &str,
    peer_id_want: &str,
    cbor_want: &str,
    ch_want: &str,
) {
    assert_eq!(pub_hex, pub_want, "{tag}: pubkey");
    assert_eq!(peer_id, peer_id_want, "{tag}: peer_id");
    assert_eq!(pin.data_cbor_hex, cbor_want, "{tag}: peer.data CBOR");
    assert_eq!(hex(&pin.content_hash.to_bytes()), ch_want, "{tag}: content_hash");
}

#[test]
fn matrix_m2_cross_key_same_hash() {
    let a = Ed448Keypair::from_seed(&[0x42; ED448_SECRET_KEY_LEN]).expect("seed A");
    let b = Keypair::from_seed([0x43; 32]);

    let pin_a = derive_peer_pin(&a.public_key_bytes(), KeyType::Ed448, HASH_ALGORITHM_SHA256);
    let pin_b = derive_peer_pin(&b.public_key_bytes(), KeyType::Ed25519, HASH_ALGORITHM_SHA256);
    assert_peer(
        "M2-A", &pin_a, &hex(&a.public_key_bytes()), M2_A_PUBKEY,
        a.peer_id().as_str(), M2_A_PEER_ID, M2_A_PEER_CBOR, M2_A_CONTENT_HASH,
    );
    assert_peer(
        "M2-B", &pin_b, &hex(&b.public_key_bytes()), M2_B_PUBKEY,
        b.peer_id().as_str(), M2_B_PEER_ID, M2_B_PEER_CBOR, M2_B_CONTENT_HASH,
    );

    let (cap_cbor, cap_ch) =
        build_root_cap(&pin_a.content_hash, &pin_b.content_hash, HASH_ALGORITHM_SHA256);
    assert_eq!(cap_cbor, M2_CAP_CBOR, "M2: cap-token CBOR");
    assert_eq!(hex(&cap_ch.to_bytes()), M2_CAP_CONTENT_HASH, "M2: cap-token content_hash");

    let sig = a.sign(&cap_ch.to_bytes());
    assert_eq!(hex(&sig), M2_CAP_SIG, "M2: signature");
}

#[test]
fn matrix_m3_cross_hash_same_key() {
    let a = Keypair::from_seed([0x44; 32]);
    let b = Keypair::from_seed([0x45; 32]);

    // A home = SHA-384, B home = SHA-256 (SEEDS.md §2.1).
    let pin_a = derive_peer_pin(&a.public_key_bytes(), KeyType::Ed25519, HASH_ALGORITHM_SHA384);
    let pin_b = derive_peer_pin(&b.public_key_bytes(), KeyType::Ed25519, HASH_ALGORITHM_SHA256);
    assert_peer(
        "M3-A", &pin_a, &hex(&a.public_key_bytes()), M3_A_PUBKEY,
        a.peer_id().as_str(), M3_A_PEER_ID, M3_A_PEER_CBOR, M3_A_CONTENT_HASH,
    );
    assert_peer(
        "M3-B", &pin_b, &hex(&b.public_key_bytes()), M3_B_PUBKEY,
        b.peer_id().as_str(), M3_B_PEER_ID, M3_B_PEER_CBOR, M3_B_CONTENT_HASH,
    );

    // Active = SHA-256 even though A's home is SHA-384 (SEEDS.md §2.2).
    let (cap_cbor, cap_ch) =
        build_root_cap(&pin_a.content_hash, &pin_b.content_hash, HASH_ALGORITHM_SHA256);
    assert_eq!(cap_cbor, M3_CAP_CBOR, "M3: cap-token CBOR");
    assert_eq!(hex(&cap_ch.to_bytes()), M3_CAP_CONTENT_HASH, "M3: cap-token content_hash");

    let sig = a.sign(&cap_ch.to_bytes());
    assert_eq!(hex(&sig), M3_CAP_SIG, "M3: signature");
}

#[test]
fn matrix_m6_cross_key_cross_hash() {
    let a = Ed448Keypair::from_seed(&[0x46; ED448_SECRET_KEY_LEN]).expect("seed A");
    let b = Keypair::from_seed([0x47; 32]);

    // A Ed448 home = SHA-384, B Ed25519 home = SHA-256 (SEEDS.md §2.1).
    let pin_a = derive_peer_pin(&a.public_key_bytes(), KeyType::Ed448, HASH_ALGORITHM_SHA384);
    let pin_b = derive_peer_pin(&b.public_key_bytes(), KeyType::Ed25519, HASH_ALGORITHM_SHA256);
    assert_peer(
        "M6-A", &pin_a, &hex(&a.public_key_bytes()), M6_A_PUBKEY,
        a.peer_id().as_str(), M6_A_PEER_ID, M6_A_PEER_CBOR, M6_A_CONTENT_HASH,
    );
    assert_peer(
        "M6-B", &pin_b, &hex(&b.public_key_bytes()), M6_B_PUBKEY,
        b.peer_id().as_str(), M6_B_PEER_ID, M6_B_PEER_CBOR, M6_B_CONTENT_HASH,
    );

    let (cap_cbor, cap_ch) =
        build_root_cap(&pin_a.content_hash, &pin_b.content_hash, HASH_ALGORITHM_SHA256);
    assert_eq!(cap_cbor, M6_CAP_CBOR, "M6: cap-token CBOR");
    assert_eq!(hex(&cap_ch.to_bytes()), M6_CAP_CONTENT_HASH, "M6: cap-token content_hash");

    let sig = a.sign(&cap_ch.to_bytes());
    assert_eq!(hex(&sig), M6_CAP_SIG, "M6: signature");
}
