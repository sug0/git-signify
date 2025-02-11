//! Verify signatures stored under git references
//! with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::raw::verify::verify;
use crate::utils;

/// Execute the `verify` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    for (path, public_key) in utils::get_public_keys(key_path)? {
        let tree_rev = {
            let object_oid = repo
                .revparse_single(&rev)
                .context("Failed to look-up git object")?
                .id();
            let key_fingerprint = public_key.fingerprint()?;
            utils::craft_signature_reference(key_fingerprint, object_oid)
        };
        if verify(&repo, &public_key, &tree_rev, false)?.is_right() {
            println!("Signature verified successfully with {}", path.display());
        } else {
            println!("No signature found for key {}", path.display());
        }
    }
    Ok(())
}
