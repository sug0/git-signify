//! Pull data from a remote repo.

use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::utils::ALL_SIGNIFY_REFS;

/// Execute the `pull` command.
pub fn command(remote: String) -> Result<()> {
    let exit_code = Command::new("git")
        .arg("fetch")
        .arg(remote)
        .arg(format!("{ALL_SIGNIFY_REFS}:{ALL_SIGNIFY_REFS}"))
        .spawn()
        .context("Failed to spawn git command")?
        .wait()
        .context("Failed to wait for git command")?;
    if exit_code.success() {
        Ok(())
    } else {
        Err(anyhow!("Exit code of git: {exit_code}"))
    }
}
