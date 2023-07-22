//! Verify signatures stored under git references
//! with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::raw::verify::verify;
use crate::utils;

/// Execute the `verify` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    let public_key = utils::get_public_key(key_path)?;
    let tree_rev = {
        let object_oid = repo
            .revparse_single(&rev)
            .context("Failed to look-up git object")?
            .id();
        let key_fingerprint = utils::hash_bytes(&public_key.key()[..])?;
        utils::craft_signature_reference(key_fingerprint, object_oid)
    };
    verify(&repo, &public_key, &tree_rev, false)?;
    println!("Signature verified successfully");
    Ok(())
}
