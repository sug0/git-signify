//! List signatures stored in this repository.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use git2::{Oid, Repository};

use super::utils;

/// List signatures stored in this repository.
pub fn command(output_json: bool) -> Result<()> {
    let repo = utils::open_repository()?;

    if !output_json {
        output_signers_human(&repo)
    } else {
        output_signers_json(&repo)
    }
}

fn output_signers_human(repo: &Repository) -> Result<()> {
    for (oid, signers) in find_signers(repo)? {
        let signed_rev = describe_object(repo, oid)?;
        println!("Signers of {signed_rev}:");

        for signer in signers {
            println!("  - {signer}");
        }
    }
    Ok(())
}

fn output_signers_json(repo: &Repository) -> Result<()> {
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

    let mut objs_iter = find_signers(repo)?.into_iter();

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
    let object = repo
        .find_object(oid, None)
        .context("Failed to find signed object")?;

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

fn find_signers(repo: &Repository) -> Result<BTreeMap<Oid, Vec<Oid>>> {
    let mut signers: BTreeMap<_, Vec<_>> = BTreeMap::new();

    for maybe_rev in repo
        .references_glob(utils::ALL_SIGNIFY_SIGNATURE_REFS)
        .context("Failed to look-up all git-signify signature refs")?
    {
        let rev = maybe_rev.context("Failed to parse git revision")?;
        let revname = rev.name().context("Invalid revision name")?;

        let Some(("", signer_and_oid)) =
            revname.split_once(utils::ALL_SIGNIFY_SIGNATURE_REFS_PREFIX)
        else {
            continue;
        };
        let Some((signer, oid)) = signer_and_oid.split_once('/') else {
            continue;
        };

        let oid = Oid::from_str(oid)
            .with_context(|| format!("Failed to parse git oid={oid} of signed obj"))?;
        let signer = Oid::from_str(signer)
            .with_context(|| format!("Failed to parse git signer with oid={oid}"))?;

        signers.entry(oid).or_default().push(signer);
    }

    Ok(signers)
}
