//! Verify signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::Result;
use git2::{Oid, Repository};

use crate::utils;

/// Execute the `verify` command.
pub fn command(key_path: PathBuf, recover: bool, tree_rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    for public_key in utils::get_public_keys(key_path)?.into_values() {
        let recovered_oid = verify(&repo, &public_key, &tree_rev, recover)?;
        if let Some(recovered_oid) = recovered_oid {
            println!("{recovered_oid}");
        }
    }
    Ok(())
}

/// Verify the signature under `tree_rev` with the given public key.
pub fn verify(
    repo: &Repository,
    public_key: &utils::PublicKey,
    tree_rev: &str,
    recover: bool,
) -> Result<Option<Oid>> {
    let tree_sig = utils::TreeSignature::load(repo, tree_rev)?;
    tree_sig.verify(public_key)?;
    recover.then(|| tree_sig.dereference()).transpose()
}
