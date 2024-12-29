//! Create signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use either::*;
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
    let object_mode_or_commit = match object
        .kind()
        .context("Failed to determine object kind to sign")?
    {
        ObjectType::Blob => Left(0o100644),
        ObjectType::Tree => Left(0o040000),
        ObjectType::Commit => Right(object.as_commit().expect("The object is a commit")),
        ty @ (ObjectType::Any | ObjectType::Tag) => {
            anyhow::bail!("Unsupported or recursive object type {ty}");
        }
    };

    let commit_author = repo
        .signature()
        .context("Failed to retrieve commit author")?;

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
        .insert("signature", signature_blob, 0o100644)
        .context("Failed to write signature to the tree")?;

    let parents = object_mode_or_commit.either(
        |object_mode| {
            tree_builder
                .insert("object", object_ptr, object_mode)
                .context("Failed to write object to the tree")?;
            anyhow::Ok(vec![])
        },
        |commit| anyhow::Ok(vec![commit]),
    )?;

    let tree_oid = tree_builder
        .write()
        .context("Failed to write tree to the object store")?;
    let tree = repo
        .find_tree(tree_oid)
        .context("Failed to look-up newly created git tree signature")?;

    let commit_oid = repo
        .commit(
            None,
            &commit_author,
            &commit_author,
            &format!("git-signify signature over {rev}"),
            &tree,
            &parents,
        )
        .context("Failed to create git signature commit")?;

    Ok(commit_oid)
}
