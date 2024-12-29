//! Catch-all utilities module.

use std::error;
use std::fmt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use git2::{Blob, ObjectType, Oid, Repository, RepositoryOpenFlags};
use libsignify::{Codeable, Signature};
use zeroize::Zeroizing;

/// Private key used to sign git objects.
pub enum PrivateKey {
    /// Private key originating from [`libsignify`].
    Signify(libsignify::PrivateKey),
}

impl PrivateKey {
    /// Return the [`PublicKey`] associated with this [`PrivateKey`].
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Signify(private_key) => PublicKey::Signify(private_key.public()),
        }
    }

    /// Sign a message using the given private key.
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Vec<u8> {
        match self {
            Self::Signify(private_key) => private_key.sign(msg.as_ref()).as_bytes(),
        }
    }
}

/// Public key used to verify signed git objects.
pub enum PublicKey {
    /// Public key originating from [`libsignify`].
    Signify(libsignify::PublicKey),
}

impl PublicKey {
    /// Compute the fingerprint of the given public key.
    pub fn fingerprint(&self) -> Result<Oid> {
        match self {
            Self::Signify(public_key) => {
                hash_bytes(public_key.key()).context("Failed to compute public key fingerprint")
            }
        }
    }
}

/// Enumeration of all possible versions of a [`TreeSignature`].
pub enum TreeSignatureVersion {
    /// Version 0 tree signatures.
    V0,
}

/// Enumeration of all possible algorithms of a [`TreeSignature`].
pub enum TreeSignatureAlgo {
    /// Signify key.
    Signify,
}

impl TreeSignatureAlgo {
    /// Parse a [`TreeSignatureAlgo`] from a git [`Blob`].
    pub fn from_blob(blob: Blob<'_>) -> Result<Self> {
        match blob.content() {
            b"signify" => Ok(Self::Signify),
            blob => Err(anyhow!(
                "Invalid tree signature algorithm {:?}",
                String::from_utf8_lossy(blob)
            )),
        }
    }
}

impl TreeSignatureVersion {
    /// Parse a [`TreeSignatureVersion`] from a git [`Blob`].
    pub fn from_blob(blob: Blob<'_>) -> Result<Self> {
        Err(anyhow!(
            "Invalid tree signature version {:?}",
            String::from_utf8_lossy(blob.content())
        ))
    }

    /// Return the current version.
    #[allow(dead_code)]
    pub const fn current() -> Self {
        TreeSignatureVersion::V0
    }
}

/// A signature stored in a git tree object.
pub struct TreeSignature<'repo> {
    /// Version of the tree signature.
    #[allow(dead_code)]
    pub version: TreeSignatureVersion,
    /// Algorithm of the tree signature.
    #[allow(dead_code)]
    pub algorithm: TreeSignatureAlgo,
    /// Pointer to the object that was signed.
    pub object_pointer: Blob<'repo>,
    /// The signature over the git object.
    pub signature: Blob<'repo>,
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

        let (version, algorithm) = tree.get_name("version").map_or(
            Ok((TreeSignatureVersion::V0, TreeSignatureAlgo::Signify)),
            |version_tree_entry| {
                let version_obj = version_tree_entry
                    .to_object(repo)
                    .context("The tree signature version could not be retrieved")?;
                let version_blob = match version_obj.into_blob() {
                    Ok(blob) => blob,
                    Err(_) => {
                        return Err(anyhow!("The tree signature version object is not a blob"))
                    }
                };
                let version = TreeSignatureVersion::from_blob(version_blob)?;

                let algorithm_obj = tree
                    .get_name("algorithm")
                    .context("Failed to look-up tree signature algorithm")?
                    .to_object(repo)
                    .context("The tree signature algorithm could not be retrieved")?;
                let algorithm_blob = match algorithm_obj.into_blob() {
                    Ok(blob) => blob,
                    Err(_) => {
                        return Err(anyhow!("The tree signature algorithm object is not a blob"))
                    }
                };
                let algorithm = TreeSignatureAlgo::from_blob(algorithm_blob)?;

                anyhow::Ok((version, algorithm))
            },
        )?;

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
            signature
                .into_blob()
                .map_err(|_| anyhow!("The signature object in {oid} is not a blob"))?
        };

        Ok(Self {
            version,
            algorithm,
            signature,
            object_pointer,
        })
    }

    /// Verify the authenticity of this [`TreeSignature`].
    pub fn verify(&self, public_key: &PublicKey) -> Result<()> {
        match (&self.algorithm, public_key) {
            (TreeSignatureAlgo::Signify, PublicKey::Signify(public_key)) => {
                let signature = Signature::from_bytes(self.signature.content())
                    .map_err(Error::new)
                    .context("Failed to parse signify signature from git blob")?;

                let dereferenced_obj = self.object_pointer.content();

                public_key
                    .verify(dereferenced_obj, &signature)
                    .map_err(Error::new)
                    .context("Failed to verify signature")
            }
        }
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
fn hash_bytes<T: AsRef<[u8]>>(bytes: T) -> Result<Oid> {
    Oid::hash_object(ObjectType::Blob, bytes.as_ref()).context("Failed to hash bytes")
}

/// Determine the format of the given key data.
fn determine_key_format(key_data: &str) -> Result<TreeSignatureAlgo> {
    const UNTRUSTED_COMMENT: &str = "untrusted comment: ";

    let Some(("", rest)) = key_data.split_once(UNTRUSTED_COMMENT) else {
        anyhow::bail!("Unknown key format");
    };

    match rest {
        s if s.starts_with("signify") => Ok(TreeSignatureAlgo::Signify),
        s if s.starts_with("minisign") => {
            todo!("minisign keys aren't supported yet")
        }
        _ => Err(anyhow!("Unknown key format")),
    }
}

/// Read a public key from the given path.
pub fn get_public_key(path: PathBuf) -> Result<PublicKey> {
    let key_data = std::fs::read_to_string(path).context("Failed to read public key")?;

    Ok(match determine_key_format(&key_data)? {
        TreeSignatureAlgo::Signify => {
            let (public_key, _) = libsignify::PublicKey::from_base64(&key_data[..])
                .map_err(Error::new)
                .context("Failed to decode public key")?;

            PublicKey::Signify(public_key)
        }
    })
}

/// Read a secret key from the given path.
pub fn get_secret_key(path: PathBuf) -> Result<PrivateKey> {
    let key_data = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .context("Failed to read secret key")?;

    Ok(match determine_key_format(&key_data)? {
        TreeSignatureAlgo::Signify => {
            let (mut secret_key, _) = libsignify::PrivateKey::from_base64(&key_data[..])
                .map_err(Error::new)
                .context("Failed to decode secret key")?;

            if secret_key.is_encrypted() {
                let passphrase = rpassword::prompt_password("key passphrase: ")
                    .map(Zeroizing::new)
                    .context("Failed to read secret key password")?;

                secret_key
                    .decrypt_with_password(&passphrase)
                    .map_err(Error::new)
                    .context("Failed to decrypt secret key")?;
            }

            PrivateKey::Signify(secret_key)
        }
    })
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
