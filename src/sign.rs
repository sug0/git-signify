//! Create signatures with [`libsignify`] and store references
//! to them in git.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::raw::sign::sign;
use crate::utils;

/// Execute the `sign` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    for (path, secret_key) in utils::get_secret_keys(key_path)? {
        let signed_object = repo
            .revparse_single(&rev)
            .context("Failed to look-up object to sign")?
            .id();
        let key_fingerprint = secret_key.public_key()?.fingerprint()?;
        let reference = utils::craft_signature_reference(key_fingerprint, signed_object);
        if utils::revparse_single_ok_or_else(&repo, &reference, |_| Ok(true), || Ok(false))? {
            println!("Signature already exists with key:");
            println!("  - {}", path.display());
            println!("Signature stored under:");
            println!("  - {reference}");
            continue;
        }
        let tree_oid = sign(&repo, &secret_key, &rev)?;
        repo.reference(
            &reference, tree_oid,
            // references to signatures are non-deterministic,
            // so we should fail if we attempt to overwrite a
            // signature in our local git repository
            false, "",
        )
        .context("Failed to store reference to signature")?;
        println!("Signed with key:");
        println!("  - {}", path.display());
        println!("Signature stored under:");
        println!("  - {reference}");
    }
    Ok(())
}
