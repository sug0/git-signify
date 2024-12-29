//! Generate shell completions.

use std::io;

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::aot::{generate, Shell};

use super::Args;

/// Execute the `shell-completions` command.
pub fn command(shell: Shell) -> Result<()> {
    generate(
        shell,
        &mut Args::command(),
        "git-signify",
        &mut io::stdout(),
    );
    Ok(())
}
