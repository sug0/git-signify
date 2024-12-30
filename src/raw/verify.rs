//! Verify signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::Result;
use either::*;
use git2::{Oid, Repository};

use crate::utils;

/// Execute the `raw verify` command.
pub fn command(key_path: PathBuf, recover: bool, tree_rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    for public_key in utils::get_public_keys(key_path)?.into_values() {
        verify(&repo, &public_key, &tree_rev, recover)?.either(
            |_| anyhow::bail!("No signature found for tree {tree_rev}"),
            |recovered_oid| {
                if let Some(recovered_oid) = recovered_oid {
                    println!("{recovered_oid}");
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

/// Verify the signature under `tree_rev` with the given public key.
pub fn verify(
    repo: &Repository,
    public_key: &utils::PublicKey,
    tree_rev: &str,
    recover: bool,
) -> Result<Either<(), Option<Oid>>> {
    let Some(tree_sig) = utils::TreeSignature::load(repo, tree_rev)? else {
        return Ok(Left(()));
    };
    tree_sig.verify(public_key)?;
    recover
        .then(|| tree_sig.dereference())
        .transpose()
        .map(Right)
}
