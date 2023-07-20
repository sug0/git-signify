mod utils;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use git2::{Oid, Repository};
use libsignify::{Codeable, Signature};

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
    /// Sign an arbitrary object and return a tree with the signature
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// The object id to sign
        git_object_id: String,
    },
    /// Verify the signature contained in a tree object
    Verify {
        /// The path to the base64 encoded public key to verify with
        #[arg(short = 'k', long)]
        public_key: PathBuf,

        /// Print the id of the signed object to stdout
        #[arg(short = 'p', long)]
        print_signed_oid: bool,

        /// The git tree containing a signed object
        git_tree_oid: String,
    },
    /// Hash a key and return it
    Fingerprint {
        /// The path to the base64 encoded key to hash
        #[arg(short = 'k', long)]
        key: PathBuf,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.action {
        Action::Sign {
            secret_key,
            git_object_id: oid,
        } => sign(secret_key, oid),
        Action::Verify {
            public_key,
            print_signed_oid: recover,
            git_tree_oid: oid,
        } => verify(public_key, recover, oid),
        Action::Fingerprint { key } => fingerprint(key),
    }
}

fn verify(key_path: PathBuf, recover: bool, oid: String) -> Result<()> {
    let repo = Repository::open(".").context("Failed to open git repository")?;

    let oid = repo
        .revparse_single(&oid)
        .context("Failed to look-up git tree oid")?
        .id();
    let tree = repo
        .find_tree(oid)
        .context("No tree object found for the given revision")?;

    let object = tree
        .get_name("object")
        .context("Failed to look-up signed object in the tree")?
        .to_object(&repo)
        .context("The signed object could not be retrieved")?;
    let object = object
        .as_blob()
        .context("The signed object is not a blob")?;
    let dereferenced_obj = object.content();

    let signature = {
        let signature = tree
            .get_name("signature")
            .context("Failed to look-up signature in the tree")?
            .to_object(&repo)
            .context("The signature object could not be retrieved")?;
        let signature = signature
            .as_blob()
            .context("The signature object is not a blob")?;
        Signature::from_bytes(signature.content())
            .map_err(utils::Error::new)
            .context("Failed to parse signature")?
    };

    let public_key = utils::get_public_key(key_path)?;

    public_key
        .verify(dereferenced_obj, &signature)
        .map_err(utils::Error::new)
        .context("Failed to verify signature")?;

    if recover {
        let oid = Oid::from_bytes(dereferenced_obj).context("Failed to parse git object id")?;
        println!("{oid}");
    }

    Ok(())
}

fn sign(key_path: PathBuf, oid: String) -> Result<()> {
    let repo = Repository::open(".").context("Failed to open git repository")?;

    let oid = repo
        .revparse_single(&oid)
        .context("Failed to look-up git object id")?
        .id();

    let object_blob = repo
        .blob(oid.as_bytes())
        .context("Failed to write object id to the git store")?;

    let secret_key = utils::get_secret_key(key_path)?;
    let signature = secret_key.sign(oid.as_bytes()).as_bytes();
    let signature_blob = repo
        .blob(&signature)
        .context("Failed to write signature to the object store")?;

    let mut tree_builder = repo
        .treebuilder(None)
        .context("Failed to get a git tree object builder")?;

    // TODO: insert a tree entry containing the version of this program

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

fn fingerprint(key_path: PathBuf) -> Result<()> {
    let public_key = utils::get_public_key(key_path)?;
    let hash = utils::hash_bytes(public_key.key().as_ref())?;
    println!("{hash}");
    Ok(())
}
