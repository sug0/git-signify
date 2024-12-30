mod fingerprint;
mod list_signatures;
mod pull;
mod push;
mod raw;
mod rev_lookup;
mod rm;
mod shell_completions;
mod sign;
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
    /// Remove git-signify data
    #[command(subcommand)]
    Rm(RmAction),
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
    /// List signatures stored in this repository
    ListSignatures {
        /// Output JSON
        #[arg(long)]
        json: bool,
    },
    /// Look-up a signature revision
    RevLookup {
        /// Path to the base64 encoded public key that signed the rev
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
        public_key: PathBuf,

        /// Revision whose signature will be looked up
        git_rev: String,
    },
    /// Generate shell completions
    ShellCompletions {
        /// The shell to generate completions for
        shell: clap_complete::aot::Shell,
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

#[derive(Subcommand)]
enum RmAction {
    /// Remove git-signify signatures
    Signature {
        /// The path to the base64 encoded public key of the signer
        #[arg(short = 'k', long, env = "GIT_KEY_PUB")]
        public_key: PathBuf,

        /// The name of the remote repository, in case
        /// we wish to remove a remote signature
        #[arg(short = 'R', long)]
        remote: Option<String>,

        /// The git revision whose signature we wish to remove
        git_rev: String,
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
        Action::Rm(RmAction::Signature {
            public_key,
            git_rev,
            remote,
        }) => rm::signature::command(public_key, git_rev, remote),
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
        Action::ListSignatures { json } => list_signatures::command(json),
        Action::RevLookup {
            public_key,
            git_rev: rev,
        } => rev_lookup::command(public_key, rev),
        Action::ShellCompletions { shell } => shell_completions::command(shell),
    }
}
