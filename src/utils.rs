//! Catch-all utilities module.

use std::error;
use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result};
use git2::{ObjectType, Oid};
use libsignify::{Codeable, PrivateKey, PublicKey};
use zeroize::Zeroizing;

/// An error type.
#[derive(Debug)]
pub struct Error<E> {
    inner: E,
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<E: fmt::Display + fmt::Debug> error::Error for Error<E> {}

impl<E> Error<E> {
    /// Create a new [`Error`].
    pub fn new(inner: E) -> Self {
        Self { inner }
    }
}

/// Hash the provided bytearray and return the
/// resulting checksum.
#[inline]
pub fn hash_bytes(bytes: &[u8]) -> Result<Oid> {
    Oid::hash_object(ObjectType::Blob, bytes).context("Failed to hash bytes")
}

/// Read a public key from the given path.
pub fn get_public_key(path: PathBuf) -> Result<PublicKey> {
    let key_data = std::fs::read_to_string(path).context("Failed to read public key")?;

    let (public_key, _) = PublicKey::from_base64(&key_data[..])
        .map_err(Error::new)
        .context("Failed to decode public key")?;

    Ok(public_key)
}

/// Read a secret key from the given path.
pub fn get_secret_key(path: PathBuf) -> Result<PrivateKey> {
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
