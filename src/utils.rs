//! Catch-all utilities module.

use std::collections::BTreeMap;
use std::error;
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use git2::{Blob, Object, ObjectType, Oid, Repository, RepositoryOpenFlags};
use libsignify::Codeable;
use zeroize::Zeroizing;

/// Private key used to sign git objects.
pub enum PrivateKey {
    /// Private key originating from [`libsignify`].
    Signify(libsignify::PrivateKey),
    /// Private key originating from [`minisign`].
    Minisign(minisign::SecretKey),
}

impl PrivateKey {
    /// Return the [`PublicKey`] associated with this [`PrivateKey`].
    pub fn public_key(&self) -> Result<PublicKey> {
        match self {
            Self::Signify(private_key) => Ok(PublicKey::Signify(private_key.public())),
            Self::Minisign(private_key) => Ok(PublicKey::Minisign(
                minisign::PublicKey::from_secret_key(private_key)
                    .context("Failed to convert minisign private key to public key")?,
            )),
        }
    }

    /// Sign a message using the given private key.
    pub fn sign<T: AsRef<[u8]>>(&self, msg: T) -> Result<Vec<u8>> {
        match self {
            Self::Signify(private_key) => Ok(private_key
                .sign(msg.as_ref())
                .to_file_encoding("signed with git-signify via libsignify")),
            Self::Minisign(private_key) => {
                let signature_box =
                    minisign::sign(None, private_key, Cursor::new(msg.as_ref()), None, None)
                        .context("Failed to sign git object with minisign private key")?;
                Ok(String::from(signature_box).into_bytes())
            }
        }
    }

    /// Return the algorithm of this [`PrivateKey`].
    pub const fn algorithm(&self) -> TreeSignatureAlgo {
        match self {
            Self::Signify(_) => TreeSignatureAlgo::Signify,
            Self::Minisign(_) => TreeSignatureAlgo::Minisign,
        }
    }
}

/// Public key used to verify signed git objects.
pub enum PublicKey {
    /// Public key originating from [`libsignify`].
    Signify(libsignify::PublicKey),
    /// Public key originating from [`minisign`].
    Minisign(minisign::PublicKey),
}

impl PublicKey {
    /// Compute the fingerprint of the given public key.
    pub fn fingerprint(&self) -> Result<Oid> {
        match self {
            Self::Signify(public_key) => hash_bytes(public_key.key())
                .context("Failed to compute signify public key fingerprint"),
            Self::Minisign(public_key) => hash_bytes(public_key.to_bytes())
                .context("Failed to compute minisign public key fingerprint"),
        }
    }
}

/// Enumeration of all possible versions of a [`TreeSignature`].
pub enum TreeSignatureVersion {
    /// Version 0 tree signatures.
    V0,
    /// Version 1 tree signatures.
    V1,
}

impl TreeSignatureVersion {
    /// Parse a [`TreeSignatureVersion`] from a git [`Blob`].
    pub fn from_blob(blob: Blob<'_>) -> Result<Self> {
        match blob.content() {
            b"v0" => Ok(Self::V0),
            b"v1" => Ok(Self::V1),
            blob => Err(anyhow!(
                "Invalid tree signature version {:?}",
                String::from_utf8_lossy(blob)
            )),
        }
    }

    /// Return the current version.
    pub const fn current() -> Self {
        TreeSignatureVersion::V1
    }

    /// Encode the version as a string.
    pub const fn as_str(&self) -> &str {
        match self {
            Self::V0 => "v0",
            Self::V1 => "v1",
        }
    }
}

/// Enumeration of all possible algorithms of a [`TreeSignature`].
pub enum TreeSignatureAlgo {
    /// Signify key.
    Signify,
    /// Minisign key.
    Minisign,
}

impl TreeSignatureAlgo {
    /// Parse a [`TreeSignatureAlgo`] from a git [`Blob`].
    pub fn from_blob(blob: Blob<'_>) -> Result<Self> {
        match blob.content() {
            b"signify" => Ok(Self::Signify),
            b"minisign" => Ok(Self::Minisign),
            blob => Err(anyhow!(
                "Invalid tree signature algorithm {:?}",
                String::from_utf8_lossy(blob)
            )),
        }
    }

    /// Encode the algorithm as a string.
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Signify => "signify",
            Self::Minisign => "minisign",
        }
    }
}

/// A signature stored in a git tree object.
pub struct TreeSignature<'repo> {
    /// Version of the tree signature.
    pub version: TreeSignatureVersion,
    /// Algorithm of the tree signature.
    pub algorithm: TreeSignatureAlgo,
    /// Pointer to the object that was signed.
    pub object_pointer: Object<'repo>,
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
        let object = repo
            .find_object(oid, None)
            .context("No git object found for the given revision")?;

        match object.kind().context(
            "Failed to determine kind of git object, while determining version of the signature",
        )? {
            ObjectType::Tree => Self::load_obj_v0(repo, object),
            ObjectType::Commit => Self::load_obj_v1_or_greater(repo, object),
            _ => anyhow::bail!(
                "Invalid object kind provided, while loading tree signature with oid={oid}"
            ),
        }
    }

    /// Load a v0 [`TreeSignature`].
    fn load_obj_v0(repo: &'repo Repository, object: Object<'repo>) -> Result<Self> {
        let tree = object.as_tree().with_context(|| {
            format!(
                "No tree signature found for object with oid={}",
                object.id()
            )
        })?;

        let object_pointer = tree
            .get_name("object")
            .context("Failed to look-up signed object in the tree")?
            .to_object(repo)
            .context("The signed object could not be retrieved")?;
        let signature = {
            let signature = tree
                .get_name("signature")
                .context("Failed to look-up signature in the tree")?
                .to_object(repo)
                .context("The signature object could not be retrieved")?;
            signature
                .into_blob()
                .map_err(|_| anyhow!("The signature object in oid={} is not a blob", object.id()))?
        };

        Ok(Self {
            signature,
            object_pointer,
            version: TreeSignatureVersion::V0,
            algorithm: TreeSignatureAlgo::Signify,
        })
    }

    /// Load a v1 [`TreeSignature`].
    fn load_obj_v1_or_greater(repo: &'repo Repository, object: Object<'repo>) -> Result<Self> {
        let commit = object
            .as_commit()
            .context("Failed to retrieve v1 git commit with signature")?;
        let tree = commit
            .tree()
            .context("Failed to retrieve v1 git tree with signature")?;

        let version = {
            let version_obj = tree
                .get_name("version")
                .context("Failed to look-up tree signature version")?
                .to_object(repo)
                .context("The tree signature version could not be retrieved")?;
            let version_blob = match version_obj.into_blob() {
                Ok(blob) => blob,
                Err(_) => return Err(anyhow!("The tree signature version object is not a blob")),
            };
            TreeSignatureVersion::from_blob(version_blob)?
        };
        let algorithm = {
            let algorithm_obj = tree
                .get_name("algorithm")
                .context("Failed to look-up tree signature algorithm")?
                .to_object(repo)
                .context("The tree signature algorithm could not be retrieved")?;
            let algorithm_blob = match algorithm_obj.into_blob() {
                Ok(blob) => blob,
                Err(_) => return Err(anyhow!("The tree signature algorithm object is not a blob")),
            };
            TreeSignatureAlgo::from_blob(algorithm_blob)?
        };

        let object_pointer = tree.get_name("object").map_or_else(
            || {
                Ok(commit
                    .parent(0)
                    .context(
                        "No signed `object` in the tree signature nor a parent commit \
                             to be signed could be found",
                    )?
                    .into_object())
            },
            |entry| {
                entry.to_object(repo).with_context(|| {
                    format!(
                        "The signed object with oid={} could not be cast to a git object",
                        entry.id()
                    )
                })
            },
        )?;

        let signature = {
            let signature = tree
                .get_name("signature")
                .context("Failed to look-up signature in the tree")?
                .to_object(repo)
                .context("The signature object could not be retrieved")?;
            signature
                .into_blob()
                .map_err(|_| anyhow!("The signature object in oid={} is not a blob", object.id()))?
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
        self.check_compatibility(public_key)
            .context("Incompatible public key provided")?;

        match public_key {
            PublicKey::Signify(public_key) => {
                let signature = match &self.version {
                    TreeSignatureVersion::V0 => {
                        libsignify::Signature::from_bytes(self.signature.content())
                            .map_err(Error::new)
                            .context("Failed to parse signify signature from git blob")?
                    }
                    TreeSignatureVersion::V1 => {
                        let signature_content = std::str::from_utf8(self.signature.content())
                            .context("Found non-utf8 data in signify signature content")?;

                        let (signature, _) = libsignify::Signature::from_base64(signature_content)
                            .map_err(Error::new)
                            .context("Failed to parse signify signature from git blob")?;

                        signature
                    }
                };

                let dereferenced_obj = self.dereference()?;

                public_key
                    .verify(dereferenced_obj.as_bytes(), &signature)
                    .map_err(Error::new)
                    .context("Invalid signify signature")
            }
            PublicKey::Minisign(public_key) => {
                let signature_box = match &self.version {
                    TreeSignatureVersion::V0 => {
                        anyhow::bail!("minisign public keys not supported in v0");
                    }
                    TreeSignatureVersion::V1 => {
                        let signature_content = std::str::from_utf8(self.signature.content())
                            .context("Found non-utf8 data in minisign signature content")?;

                        minisign::SignatureBox::from_string(signature_content)
                            .context("Failed to parse minisign signature from git blob")?
                    }
                };

                let dereferenced_obj = self.dereference()?;

                minisign::verify(
                    public_key,
                    &signature_box,
                    Cursor::new(dereferenced_obj.as_bytes()),
                    true,
                    false,
                    false,
                )
                .context("Invalid minisign signature")
            }
        }
    }

    /// Check the compatibility of the given public key with this
    /// tree signature.
    pub fn check_compatibility(&self, key: &PublicKey) -> Result<()> {
        match (&self.version, &self.algorithm, key) {
            (TreeSignatureVersion::V0, TreeSignatureAlgo::Signify, PublicKey::Signify(_))
            | (TreeSignatureVersion::V1, TreeSignatureAlgo::Signify, PublicKey::Signify(_))
            | (TreeSignatureVersion::V1, TreeSignatureAlgo::Minisign, PublicKey::Minisign(_)) => {
                Ok(())
            }
            _ => {
                anyhow::bail!(
                    "Attempted to validate signature with a public key of an incompatible \
                    type"
                );
            }
        }
    }

    /// Dereference the inner object pointer.
    #[inline]
    pub fn dereference(&self) -> Result<Oid> {
        match &self.version {
            TreeSignatureVersion::V0 => {
                let blob = self
                    .object_pointer
                    .as_blob()
                    .context("The signed object is not a blob")?;
                let oid_bytes = blob.content();
                Oid::from_bytes(oid_bytes).context("Failed to parse git object id from raw bytes")
            }
            TreeSignatureVersion::V1 => Ok(self.object_pointer.id()),
        }
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
        s if s.starts_with("minisign") => Ok(TreeSignatureAlgo::Minisign),
        _ => Err(anyhow!("Unknown key format")),
    }
}

/// Read all keys under the given `path` with `read`.
fn read_key_entries<F, T>(ext: &str, path: PathBuf, mut read: F) -> Result<BTreeMap<PathBuf, T>>
where
    F: FnMut(&Path) -> Result<T>,
{
    let mut keys = BTreeMap::new();

    for maybe_ent in fs::read_dir(path)
        .with_context(|| format!("Failed to query entries in {ext} key directory"))?
    {
        let ent =
            maybe_ent.with_context(|| format!("Failed to read entry in {ext} key directory"))?;
        let path = ent.path();

        if matches!(path.extension().and_then(|p| p.to_str()), Some(e) if e == ext) {
            let key = read(&path)?;
            keys.insert(path, key);
        }
    }

    Ok(keys)
}

/// Read public keys from the given path. If a directory is provided,
/// keys are read from files whose extension is `.pub`.
pub fn get_public_keys(path: PathBuf) -> Result<BTreeMap<PathBuf, PublicKey>> {
    let meta = fs::metadata(&path).context("Failed to query public key path metadata")?;

    if meta.is_dir() {
        read_key_entries("pub", path, get_public_key)
    } else {
        get_public_key(&path).map(|key| {
            let mut map = BTreeMap::new();
            map.insert(path, key);
            map
        })
    }
}

/// Read a public key from the given path.
fn get_public_key(path: &Path) -> Result<PublicKey> {
    let key_data = std::fs::read_to_string(path).context("Failed to read public key")?;

    Ok(match determine_key_format(&key_data)? {
        TreeSignatureAlgo::Signify => {
            let (public_key, _) = libsignify::PublicKey::from_base64(&key_data[..])
                .map_err(Error::new)
                .context("Failed to decode signify public key")?;

            PublicKey::Signify(public_key)
        }
        TreeSignatureAlgo::Minisign => {
            let public_key = minisign::PublicKeyBox::from_string(&key_data[..])
                .context("Failed to read minisign public key")?;

            PublicKey::Minisign(
                public_key
                    .into_public_key()
                    .context("Failed to decode minisign public key")?,
            )
        }
    })
}

/// Read secret keys from the given path. If a directory is provided,
/// keys are read from files whose extension is `.sec`.
pub fn get_secret_keys(path: PathBuf) -> Result<BTreeMap<PathBuf, PrivateKey>> {
    let meta = fs::metadata(&path).context("Failed to query secret key path metadata")?;

    if meta.is_dir() {
        read_key_entries("sec", path, get_secret_key)
    } else {
        get_secret_key(&path).map(|key| {
            let mut map = BTreeMap::new();
            map.insert(path, key);
            map
        })
    }
}

/// Read a secret key from the given path.
fn get_secret_key(path: &Path) -> Result<PrivateKey> {
    let key_data = std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .context("Failed to read secret key")?;

    Ok(match determine_key_format(&key_data)? {
        TreeSignatureAlgo::Signify => {
            let (mut secret_key, _) = libsignify::PrivateKey::from_base64(&key_data[..])
                .map_err(Error::new)
                .context("Failed to decode secret key")?;

            if secret_key.is_encrypted() {
                let passphrase = prompt_key_passphrase().map(Zeroizing::new)?;

                secret_key
                    .decrypt_with_password(&passphrase)
                    .map_err(Error::new)
                    .context("Failed to decrypt secret key")?;
            }

            PrivateKey::Signify(secret_key)
        }
        TreeSignatureAlgo::Minisign => {
            let private_key = minisign::SecretKeyBox::from_string(&key_data[..])
                .context("Failed to read minisign secret key")?;

            let passphrase = prompt_key_passphrase()?;

            PrivateKey::Minisign(
                private_key
                    .into_secret_key(Some(passphrase))
                    .context("Failed to decode minisign private key")?,
            )
        }
    })
}

fn prompt_key_passphrase() -> Result<String> {
    rpassword::prompt_password("key passphrase: ").context("Failed to read secret key passphrase")
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

/// Git refspec describing all signify signature references.
pub const ALL_SIGNIFY_SIGNATURE_REFS: &str = "refs/signify/signatures/*";

/// Git refspec prefix describing all signify signature references.
pub const ALL_SIGNIFY_SIGNATURE_REFS_PREFIX: &str = "refs/signify/signatures/";
