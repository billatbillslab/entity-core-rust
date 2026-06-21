pub mod identity;
pub mod peer;

use entity_core::crypto::{Ed448Keypair, IdentityKeypair, Keypair};

/// Mint a fresh signing identity for the requested `key_type` string
/// (v7.67 Phase 2 — CLI `--key-type {ed25519,ed448}`). Ed25519 is the
/// default/back-compat path; ed448 mints a 57-byte-seed Ed448 identity.
pub(crate) fn mint_identity(key_type: &str) -> anyhow::Result<IdentityKeypair> {
    match key_type {
        "ed25519" => Ok(IdentityKeypair::Ed25519(Keypair::generate())),
        "ed448" => Ok(IdentityKeypair::Ed448(Ed448Keypair::generate())),
        other => anyhow::bail!(
            "unsupported --key-type {:?} (expected ed25519 or ed448)",
            other
        ),
    }
}
