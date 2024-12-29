mod fingerprint;
mod pull;
mod push;
mod raw;
mod sign;
mod store;
mod utils;
mod verify;

use std::borrow::Cow;
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
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
        key: PathBuf,
    },
    /// Sign an arbitrary object
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long, env = "GIT_KEY_SEC")]
        secret_key: PathBuf,

        /// The git revision to sign
        git_rev: String,
    },
    /// Verify the signature over some git revision
    Verify {
        /// The path to the base64 encoded public key to verify with
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
        public_key: PathBuf,

        /// The signed git revision to verify
        git_rev: String,
    },
    /// Push signify data to a remote repository
    Push {
        /// The name of the remote repository
        remote: Option<Cow<'static, str>>,
    },
    /// Pull signify data from a remote repository
    Pull {
        /// The name of the remote repository
        remote: Option<Cow<'static, str>>,
    },
    /// Store a reference to a public key
    Store {
        /// The path to the base64 encoded public key to store
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
        key: PathBuf,
    },
}

#[derive(Subcommand)]
enum RawAction {
    /// Sign an arbitrary object and return a tree with the signature
    Sign {
        /// The path to the base64 encoded secret key to sign with
        #[arg(short = 'k', long, env = "GIT_KEY_SEC")]
        secret_key: PathBuf,

        /// The git revision to sign
        git_rev: String,
    },
    /// Verify the signature contained in a tree object
    Verify {
        /// The path to the base64 encoded public key to verify with
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
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
        Action::Verify {
            public_key,
            git_rev: rev,
        } => verify::command(public_key, rev),
        Action::Push { remote } => push::command(&remote.unwrap_or(Cow::Borrowed("origin"))),
        Action::Pull { remote } => pull::command(&remote.unwrap_or(Cow::Borrowed("origin"))),
        Action::Store { key } => store::command(key),
    }
}
