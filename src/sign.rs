//! Create signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use git2::{Oid, Repository};
use libsignify::{Codeable, PrivateKey};

use super::utils;

/// Execute the `sign` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = Repository::open(".").context("Failed to open git repository")?;
    let secret_key = utils::get_secret_key(key_path)?;
    let tree_oid = sign(&repo, &secret_key, &rev)?;
    println!("{tree_oid}");
    Ok(())
}

/// Sign the revision `rev` with the secret key `key`, write the results
/// to `repo`, and return the corresponding object id of the signature tree.
pub fn sign(repo: &Repository, secret_key: &PrivateKey, rev: &str) -> Result<Oid> {
    let oid = repo
        .revparse_single(rev)
        .context("Failed to look-up git object id")?
        .id();

    let object_blob = repo
        .blob(oid.as_bytes())
        .context("Failed to write object id to the git store")?;

    let signature = secret_key.sign(oid.as_bytes()).as_bytes();
    let signature_blob = repo
        .blob(&signature)
        .context("Failed to write signature to the object store")?;

    let mut tree_builder = repo
        .treebuilder(None)
        .context("Failed to get a git tree object builder")?;

    // TODO: insert a tree entry containing the version of this program

    tree_builder
        .insert("object", object_blob, 0o100644)
        .context("Failed to write object to the tree")?;
    tree_builder
        .insert("signature", signature_blob, 0o100644)
        .context("Failed to write signature to the tree")?;

    let tree_oid = tree_builder
        .write()
        .context("Failed to write tree to the object store")?;

    Ok(tree_oid)
}
