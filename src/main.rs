mod fingerprint;
mod raw;
mod sign;
mod utils;
//mod verify;

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
    /// Primitive signing and verification commands
    #[command(subcommand)]
    Raw(RawAction),
    /// Hash a key and return it
    Fingerprint {
        /// The path to the base64 encoded key to hash
        #[arg(short = 'k', long)]
        key: PathBuf,
    },
    /// Sign an arbitrary object
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// The git revision to sign
        git_rev: String,
    },
}

#[derive(Subcommand)]
enum RawAction {
    /// Sign an arbitrary object and return a tree with the signature
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long)]
        secret_key: PathBuf,

        /// The git revision to sign
        git_rev: String,
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
        git_tree: String,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.action {
        Action::Raw(RawAction::Sign {
            secret_key,
            git_rev: rev,
        }) => raw::sign::command(secret_key, rev),
        Action::Raw(RawAction::Verify {
            public_key,
            print_signed_oid: recover,
            git_tree: rev,
        }) => raw::verify::command(public_key, recover, rev),
        Action::Fingerprint { key } => fingerprint::command(key),
        Action::Sign {
            secret_key,
            git_rev: rev,
        } => sign::command(secret_key, rev),
    }
}
