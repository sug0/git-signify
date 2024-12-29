//! Create signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use git2::{ObjectType, Oid, Repository};

use crate::utils;

/// Execute the `sign` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    let secret_key = utils::get_secret_key(key_path)?;
    let tree_oid = sign(&repo, &secret_key, &rev)?;
    println!("{tree_oid}");
    Ok(())
}

/// Sign the revision `rev` with the given secret key, write the results
/// to `repo` and return the object id of the resulting signature tree.
pub fn sign(repo: &Repository, secret_key: &utils::PrivateKey, rev: &str) -> Result<Oid> {
    let object = repo
        .revparse_single(rev)
        .context("Failed to look-up git object id")?;

    let object_ptr = object.id();
    let object_mode = match object
        .kind()
        .context("Failed to determine object kind to sign")?
    {
        ObjectType::Blob => 0o100644,
        ObjectType::Tree => 0o040000,
        ty @ (ObjectType::Any | ObjectType::Commit | ObjectType::Tag) => {
            anyhow::bail!("Unsupported object type {ty}");
        }
    };

    let signature = secret_key.sign(object_ptr.as_bytes())?;
    let signature_blob = repo
        .blob(&signature)
        .context("Failed to write signature to the object store")?;

    let version_blob = repo
        .blob(utils::TreeSignatureVersion::current().as_str().as_bytes())
        .context("Failed to write tree signature version to the object store")?;

    let algo_blob = repo
        .blob(secret_key.algorithm().as_str().as_bytes())
        .context("Failed to write tree signature algorithm to the object store")?;

    let mut tree_builder = repo
        .treebuilder(None)
        .context("Failed to get a git tree object builder")?;

    tree_builder
        .insert("version", version_blob, 0o100644)
        .context("Failed to write version to the tree")?;
    tree_builder
        .insert("algorithm", algo_blob, 0o100644)
        .context("Failed to write algorithm to the tree")?;
    tree_builder
        .insert("object", object_ptr, object_mode)
        .context("Failed to write object to the tree")?;
    tree_builder
        .insert("signature", signature_blob, 0o100644)
        .context("Failed to write signature to the tree")?;

    let tree_oid = tree_builder
        .write()
        .context("Failed to write tree to the object store")?;

    Ok(tree_oid)
}
