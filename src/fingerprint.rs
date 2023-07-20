//! Return the fingerprint of some key.

use std::path::PathBuf;

use anyhow::Result;

use super::utils;

/// Execute the `fingerprint` command.
pub fn command(key_path: PathBuf) -> Result<()> {
    let public_key = utils::get_public_key(key_path)?;
    let hash = utils::hash_bytes(public_key.key().as_ref())?;
    println!("{hash}");
    Ok(())
}
