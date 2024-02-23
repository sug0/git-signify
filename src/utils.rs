//! Catch-all utilities module.

use std::error;
use std::fmt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use git2::{Blob, ObjectType, Oid, Repository, RepositoryOpenFlags};
use libsignify::{Codeable, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

/// A signature stored in a git tree object.
pub struct TreeSignature<'repo> {
    /// Pointer to the object that was signed.
    pub object_pointer: Blob<'repo>,
    /// The signature over the git object.
    pub signature: Signature,
}

impl<'repo> TreeSignature<'repo> {
    /// Load a [`TreeSignature`] at the given `tree_rev` from the
    /// provided git repository.
    #[inline]
    pub fn load(repo: &'repo Repository, tree_rev: &str) -> Result<Self> {
        let oid = repo
            .revparse_single(tree_rev)
            .context("Failed to look-up git tree oid")?
            .id();
        Self::load_oid(repo, oid)
    }

    /// Like [`TreeSignature::load`], but uses a concrete revision pointing
    /// to the tree signature.
    pub fn load_oid(repo: &'repo Repository, oid: Oid) -> Result<Self> {
        let tree = repo
            .find_tree(oid)
            .context("No tree object found for the given revision")?;

        let object = tree
            .get_name("object")
            .context("Failed to look-up signed object in the tree")?
            .to_object(repo)
            .context("The signed object could not be retrieved")?;
        let object_pointer = match object.into_blob() {
            Ok(ptr) => ptr,
            Err(_) => return Err(anyhow!("The signed object is not a blob")),
        };

        let signature = {
            let signature = tree
                .get_name("signature")
                .context("Failed to look-up signature in the tree")?
                .to_object(repo)
                .context("The signature object could not be retrieved")?;
            let signature = signature
                .as_blob()
                .context("The signature object is not a blob")?;
            Signature::from_bytes(signature.content())
                .map_err(Error::new)
                .context("Failed to parse signature")?
        };

        Ok(Self {
            signature,
            object_pointer,
        })
    }

    /// Verify the authenticity of this [`TreeSignature`].
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        let dereferenced_obj = self.object_pointer.content();
        public_key
            .verify(dereferenced_obj, &self.signature)
            .map_err(Error::new)
            .context("Failed to verify signature")
    }

    /// Dereference the inner object pointer.
    #[inline]
    pub fn dereference(&self) -> Result<Oid> {
        Oid::from_bytes(self.object_pointer.content()).context("Failed to parse git object id")
    }
}

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

/// Try to find and open a git repository.
pub fn open_repository() -> Result<Repository> {
    Repository::open_ext(
        ".",
        RepositoryOpenFlags::empty(),
        &[] as &[&std::ffi::OsStr],
    )
    .context("Failed to open git repository")
}

/// Craft a git reference to an object signed by a key with the given
/// fingerprint.
pub fn craft_signature_reference(key_fingerprint: Oid, signed_object: Oid) -> String {
    format!("refs/signify/signatures/{key_fingerprint}/{signed_object}")
}

/// Git refspec describing all signify references.
pub const ALL_SIGNIFY_REFS: &str = "refs/signify/*";
