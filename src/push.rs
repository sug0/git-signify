//! Push data to a remote repo.

use std::process::Command;

use anyhow::{anyhow, Context, Result};

use crate::utils::ALL_SIGNIFY_REFS;

/// Execute the `push` command.
pub fn command(remote: &str) -> Result<()> {
    let exit_code = Command::new("git")
        .arg("push")
        .arg(remote)
        .arg(ALL_SIGNIFY_REFS)
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
