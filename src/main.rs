mod fingerprint;
mod sign;
mod utils;
mod verify;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

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
        } => sign::command(secret_key, oid),
        Action::Verify {
            public_key,
            print_signed_oid: recover,
            git_tree_oid: oid,
        } => verify::command(public_key, recover, oid),
        Action::Fingerprint { key } => fingerprint::command(key),
    }
}
