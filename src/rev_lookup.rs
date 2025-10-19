//! Look-up the git revision of a signature produced by
//! `git-signify`.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::utils;

/// Execute the `rev-lookup` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    let object_oid = repo
        .revparse_single(&rev)
        .context("Failed to look-up git object")?
        .id();
    for public_key in utils::get_public_keys(key_path)?.into_values() {
        let tree_rev = {
            let key_fingerprint = public_key.fingerprint()?;
            utils::craft_signature_reference(key_fingerprint, object_oid)
        };
        if utils::revparse_single_ok_or_else(&repo, &tree_rev, |_| Ok(true), || Ok(false))? {
            println!("{tree_rev}");
        }
    }
    Ok(())
}
