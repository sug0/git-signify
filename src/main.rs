use std::error;
use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use git2::{Oid, Repository};
use libsignify::{Codeable, PrivateKey};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct Error<E> {
    inner: E,
}

/// A git sub-command to sign arbitrary objects
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The action to execute
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Sign an arbitrary git object
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// The object id to sign
        git_object_id: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.action {
        Action::Sign {
            secret_key,
            git_object_id: oid,
        } => sign(secret_key, oid),
    }
}

fn sign(key_path: PathBuf, oid: String) -> Result<()> {
    let repo = Repository::open(".").context("Failed to open git repository")?;

    let oid = Oid::from_str(&oid).context("Failed to parse git object id")?;
    repo.find_object(oid, None)
        .context("Failed to look-up object in the repository")?;

    let object_blob = repo
        .blob(oid.as_bytes())
        .context("Failed to write object id to the git store")?;

    let secret_key = get_secret_key(key_path)?;
    let signature = secret_key.sign(oid.as_bytes()).as_bytes();
    let signature_blob = repo
        .blob(&signature)
        .context("Failed to write signature to the object store")?;

    let mut tree_builder = repo
        .treebuilder(None)
        .context("Failed to get a git tree object builder")?;

    tree_builder
        .insert("object", object_blob, 0o100644)
        .context("Failed to write object to the tree")?;
    tree_builder
        .insert("signature", signature_blob, 0o100644)
        .context("Failed to write signature to the tree")?;

    let tree_oid = tree_builder
        .write()
        .context("Failed to write tree to the object store")?;

    println!("{tree_oid}");
    Ok(())
}

fn get_secret_key(path: PathBuf) -> Result<PrivateKey> {
    let (mut secret_key, _) = {
        let key_data = std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .context("Failed to read secret key")?;

        PrivateKey::from_base64(&key_data[..])
            .map_err(Error::new)
            .context("Failed to decode secret key")?
    };

    if secret_key.is_encrypted() {
        let passphrase = rpassword::prompt_password("key passphrase: ")
            .map(Zeroizing::new)
            .context("Failed to read secret key password")?;

        secret_key
            .decrypt_with_password(&passphrase)
            .map_err(Error::new)
            .context("Failed to decrypt secret key")?;
    }

    Ok(secret_key)
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<E: fmt::Display + fmt::Debug> error::Error for Error<E> {}

impl<E> Error<E> {
    fn new(inner: E) -> Self {
        Self { inner }
    }
}
