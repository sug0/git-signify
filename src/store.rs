//! Store git references to [`libsignify`] public keys.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::utils;

/// Execute the `store` command.
pub fn command(key_path: PathBuf) -> Result<()> {
    let repo = utils::open_repository()?;
    let public_key = utils::get_public_key(key_path)?;
    let public_key_oid = repo
        .blob(public_key.key().as_ref())
        .context("Failed to write public key to the object store")?;
    let key_fingerprint = utils::hash_bytes(public_key.key().as_ref())?;
    let reference = utils::craft_pubkey_reference(key_fingerprint);
    repo.reference(
        &reference,
        public_key_oid,
        // references to public keys will never change, so it is
        // safe to force overwriting faulty references
        true,
        "",
    )
    .context("Failed to store reference to public key")?;
    println!("Public key stored under: {reference}");
    Ok(())
}
