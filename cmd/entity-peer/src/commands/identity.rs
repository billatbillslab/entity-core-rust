//! identity create/list/show commands.

use std::fs;

use entity_core::crypto::IdentityKeypair;

use crate::config;

/// Create a new identity keypair of the requested `key_type`
/// (v7.67 Phase 2 — `--key-type {ed25519,ed448}`).
pub fn create(name: &str, key_type: &str) -> anyhow::Result<()> {
    let dir = config::identities_dir();
    fs::create_dir_all(&dir)?;

    let key_path = config::identity_key_path(name);
    if key_path.exists() {
        anyhow::bail!("identity '{}' already exists", name);
    }

    let kp = crate::commands::mint_identity(key_type)?;
    kp.save_to_file(&key_path)?;

    let peer_id = kp.peer_id();
    println!("created identity '{}'", name);
    println!("  key_type: {}", kp.key_type().label());
    println!("  peer_id:  {}", peer_id);
    println!("  key:      {}", key_path.display());
    println!("  pub:      {}", key_path.with_extension("pub").display());

    Ok(())
}

/// List all identities.
pub fn list() -> anyhow::Result<()> {
    let dir = config::identities_dir();
    if !dir.exists() {
        println!("no identities found");
        return Ok(());
    }

    let mut found = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip .pub files — we read the private key file
        if path.extension().is_some() {
            continue;
        }

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?");

        match IdentityKeypair::load_from_file(&path) {
            Ok(kp) => {
                println!("{:<20} {:<8} {}", name, kp.key_type().label(), kp.peer_id());
                found = true;
            }
            Err(e) => {
                println!("{:<20} (error: {})", name, e);
                found = true;
            }
        }
    }

    if !found {
        println!("no identities found");
    }

    Ok(())
}

/// Show details for a specific identity.
pub fn show(name: &str) -> anyhow::Result<()> {
    let key_path = config::identity_key_path(name);
    if !key_path.exists() {
        anyhow::bail!("identity '{}' not found", name);
    }

    let kp = IdentityKeypair::load_from_file(&key_path)?;
    println!("name:       {}", name);
    println!("key_type:   {}", kp.key_type().label());
    println!("peer_id:    {}", kp.peer_id());
    println!("public_key: {}", kp.public_key_base64());
    println!("key_file:   {}", key_path.display());
    println!("pub_file:   {}", key_path.with_extension("pub").display());

    Ok(())
}
