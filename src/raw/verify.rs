//! Verify signatures with [`libsignify`].

use std::path::PathBuf;

use anyhow::{Context, Result};
use git2::{Oid, Repository};
use libsignify::{Codeable, Signature};

use crate::utils;

/// Execute the `verify` command.
pub fn command(key_path: PathBuf, recover: bool, tree_rev: String) -> Result<()> {
    let repo = Repository::open(".").context("Failed to open git repository")?;

    let oid = repo
        .revparse_single(&tree_rev)
        .context("Failed to look-up git tree oid")?
        .id();
    let tree = repo
        .find_tree(oid)
        .context("No tree object found for the given revision")?;

    let object = tree
        .get_name("object")
        .context("Failed to look-up signed object in the tree")?
        .to_object(&repo)
        .context("The signed object could not be retrieved")?;
    let object = object
        .as_blob()
        .context("The signed object is not a blob")?;
    let dereferenced_obj = object.content();

    let signature = {
        let signature = tree
            .get_name("signature")
            .context("Failed to look-up signature in the tree")?
            .to_object(&repo)
            .context("The signature object could not be retrieved")?;
        let signature = signature
            .as_blob()
            .context("The signature object is not a blob")?;
        Signature::from_bytes(signature.content())
            .map_err(utils::Error::new)
            .context("Failed to parse signature")?
    };

    let public_key = utils::get_public_key(key_path)?;

    public_key
        .verify(dereferenced_obj, &signature)
        .map_err(utils::Error::new)
        .context("Failed to verify signature")?;

    if recover {
        let oid = Oid::from_bytes(dereferenced_obj).context("Failed to parse git object id")?;
        println!("{oid}");
    }

    Ok(())
}
