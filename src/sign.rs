//! Create signatures with [`libsignify`] and store references
//! to them in git.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::raw::sign::sign;
use crate::utils;

/// Execute the `sign` command.
pub fn command(key_path: PathBuf, rev: String) -> Result<()> {
    let repo = utils::open_repository()?;
    let secret_key = utils::get_secret_key(key_path)?;
    let tree_oid = sign(&repo, &secret_key, &rev)?;
    let signed_object = {
        let tree_sig = utils::TreeSignature::load_oid(&repo, tree_oid)?;
        tree_sig.dereference()?
    };
    let key_fingerprint = secret_key.public_key().fingerprint()?;
    let reference = utils::craft_signature_reference(key_fingerprint, signed_object);
    repo.reference(
        &reference, tree_oid,
        // references to signatures will never change, so it is
        // safe to force overwriting faulty references
        true, "",
    )
    .context("Failed to store reference to signature")?;
    println!("Signature stored under: {reference}");
    Ok(())
}
