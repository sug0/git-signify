//! List signatures stored in this repository.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use git2::{Oid, Repository};

use super::utils;

/// List signatures stored in this repository.
pub fn command() -> Result<()> {
    let repo = utils::open_repository()?;

    for (oid, signers) in find_signers(&repo)? {
        let object = repo
            .find_object(oid, None)
            .context("Failed to find signed object")?;

        let signed_rev = {
            let opts = {
                let mut opts = git2::DescribeOptions::new();
                opts.describe_all();
                opts.show_commit_oid_as_fallback(true);
                opts
            };
            object
                .describe(&opts)
                .with_context(|| format!("Failed to describe oid={oid}"))?
                .format(None)
                .with_context(|| format!("Failed to format description of oid={oid}"))?
        };

        println!("Signers of {signed_rev}:");

        for signer in signers {
            println!("  - {signer}");
        }
    }

    Ok(())
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
