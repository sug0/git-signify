//! Return the fingerprint of some key.

use std::path::PathBuf;

use anyhow::Result;

use super::utils;

/// Execute the `fingerprint` command.
pub fn command(key_path: PathBuf) -> Result<()> {
    for (path, public_key) in utils::get_public_keys(key_path)? {
        let hash = public_key.fingerprint()?;
        println!("{}:", path.display());
        println!("  - {hash}");
    }
    Ok(())
}
