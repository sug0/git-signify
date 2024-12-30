//! Remove git-signify signatures.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::utils;

/// Execute the `rm signature` command.
pub fn command(public_key: PathBuf, rev: String, remote: Option<String>) -> Result<()> {
    let repo = utils::open_repository()?;

    for public_key in utils::get_public_keys(public_key)?.into_values() {
        let tree_rev = {
            let object_oid = repo
                .revparse_single(&rev)
                .context("Failed to look-up git object")?
                .id();
            let key_fingerprint = public_key.fingerprint()?;
            utils::craft_signature_reference(key_fingerprint, object_oid)
        };

        if let Some(remote) = remote.as_ref() {
            let exit_code = Command::new("git")
                .arg("push")
                .arg("-d")
                .arg(remote)
                .arg(tree_rev)
                .spawn()
                .context("Failed to spawn git command to remove remote signature")?
                .wait()
                .context("Failed to wait for git command to remove remote signature")?;
            if !exit_code.success() {
                return Err(anyhow!("Exit code of git: {exit_code}"));
            }
        } else {
            let mut path = PathBuf::new();

            path.push(".git");
            path.push(tree_rev);

            fs::remove_file(path)
                .or_else(|e| {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .context("Failed to remove local git reference")?;
        }
    }

    Ok(())
}
