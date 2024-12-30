//! List signatures stored in this repository.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use git2::{Direction, Oid, ProxyOptions, Remote, Repository};

use super::utils;

/// Execute the `list-signatures` command.
pub fn command(output_json: bool, remote: Option<String>) -> Result<()> {
    let repo = utils::open_repository()?;

    if let Some(remote_name) = remote {
        let mut remote = repo
            .find_remote(&remote_name)
            .context("Unable to find remote")?;

        let proxy_options = {
            let mut opts = ProxyOptions::new();
            opts.auto();
            opts
        };

        remote
            .connect_auth(Direction::Fetch, None, Some(proxy_options))
            .with_context(|| {
                format!(
                    "Failed to connect to remote {remote_name}, only \
                     remotes with no authentication are supported",
                )
            })?;

        command_inner(&repo, output_json, &remote)
    } else {
        command_inner(&repo, output_json, &repo)
    }
}

fn command_inner<'repo, F: FindSigners + ?Sized>(
    repo: &'repo Repository,
    output_json: bool,
    find_signers: &'repo F,
) -> Result<()> {
    if !output_json {
        output_signers_human(repo, find_signers)
    } else {
        output_signers_json(repo, find_signers)
    }
}

fn output_signers_human<F: FindSigners + ?Sized>(repo: &Repository, f: &F) -> Result<()> {
    for (oid, signers) in f.find_signers()? {
        let signed_rev = describe_object(repo, oid)?;
        println!("Signers of {signed_rev}:");

        for signer in signers {
            println!("  - {signer}");
        }
    }
    Ok(())
}

fn output_signers_json<F: FindSigners + ?Sized>(repo: &Repository, f: &F) -> Result<()> {
    fn print_signers(signers: Vec<Oid>) {
        let mut signers_iter = signers.into_iter();

        print!("[");
        if let Some(signer) = signers_iter.next() {
            print!("\"{signer}\"");
        }
        for signer in signers_iter {
            print!(",\"{signer}\"");
        }
        print!("]");
    }

    let mut objs_iter = f.find_signers()?.into_iter();

    print!("{{");
    if let Some((oid, signers)) = objs_iter.next() {
        let signed_rev = describe_object(repo, oid)?;
        print!("\"{signed_rev}\":");
        print_signers(signers);
    }
    for (oid, signers) in objs_iter {
        let signed_rev = describe_object(repo, oid)?;
        print!(",\"{signed_rev}\":");
        print_signers(signers);
    }
    print!("}}");

    Ok(())
}

fn describe_object(repo: &Repository, oid: Oid) -> Result<String> {
    let Ok(object) = repo.find_object(oid, None) else {
        return Ok(oid.to_string());
    };

    let opts = {
        let mut opts = git2::DescribeOptions::new();
        opts.describe_all();
        opts.show_commit_oid_as_fallback(true);
        opts
    };

    let description = object
        .describe(&opts)
        .with_context(|| format!("Failed to describe oid={oid}"))?;

    description
        .format(None)
        .with_context(|| format!("Failed to format description of oid={oid}"))
}

trait FindSigners {
    fn find_signers(&self) -> Result<BTreeMap<Oid, Vec<Oid>>>;
}

impl FindSigners for Repository {
    fn find_signers(&self) -> Result<BTreeMap<Oid, Vec<Oid>>> {
        let mut signers: BTreeMap<_, Vec<_>> = BTreeMap::new();

        for maybe_rev in self
            .references_glob(utils::ALL_SIGNIFY_SIGNATURE_REFS)
            .context("Failed to look-up all git-signify signature refs")?
        {
            let rev = maybe_rev.context("Failed to parse git revision")?;
            let revname = rev.name().context("Invalid revision name")?;

            let Some((oid, signer)) = parse_signature_oid_and_signer(revname) else {
                continue;
            };

            signers.entry(oid).or_default().push(signer);
        }

        Ok(signers)
    }
}

impl FindSigners for Remote<'_> {
    fn find_signers(&self) -> Result<BTreeMap<Oid, Vec<Oid>>> {
        let mut signers: BTreeMap<_, Vec<_>> = BTreeMap::new();

        for (oid, signer) in self
            .list()
            .context("Failed to look-up remote refs")?
            .iter()
            .filter_map(|head| parse_signature_oid_and_signer(head.name()))
        {
            signers.entry(oid).or_default().push(signer);
        }

        Ok(signers)
    }
}

fn parse_signature_oid_and_signer(revname: &str) -> Option<(Oid, Oid)> {
    let ("", signer_and_oid) = revname.split_once(utils::ALL_SIGNIFY_SIGNATURE_REFS_PREFIX)? else {
        return None;
    };
    let (signer, oid) = signer_and_oid.split_once('/')?;

    let oid = Oid::from_str(oid).ok()?;
    let signer = Oid::from_str(signer).ok()?;

    Some((oid, signer))
}
