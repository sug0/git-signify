//! Look-up the git revision of a signature produced by
//! `git-signify`.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::utils;

/// Execute the `rev-lookup` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    let public_key = utils::get_public_key(key_path)?;
    let tree_rev = {
        let object_oid = repo
            .revparse_single(&rev)
            .context("Failed to look-up git object")?
            .id();
        let key_fingerprint = public_key.fingerprint()?;
        utils::craft_signature_reference(key_fingerprint, object_oid)
    };
    repo.revparse_single(&tree_rev)
        .with_context(|| format!("No signature found for {rev}"))?;
    println!("{tree_rev}");
    Ok(())
}
