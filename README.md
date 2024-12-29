# git-signify

A tool to sign arbitrary objects in a git repository.

## Generating keys

Signing keys can be generated with [`signify`], from the OpenBSD project.

```
$ signify -G -p newkey.pub -s newkey.sec
```

If you do not wish to encrypt your keys, pass the `-n` flag to the
command line of `signify`.

Alternatively, [`minisign`] keys may also be used. This project provides
a more portable alternative to [`signify`].

```
$ minisign -G -p newkey.pub -s newkey.sec
```

`git-signify` always assumes that [`minisign`] keys are encrypted,
albeit the CLI tool allows generating non-encrypted keys.

[`signify`]: https://man.openbsd.org/signify.1
[`minisign`]: https://github.com/jedisct1/minisign

## Basic usage

This program keeps track of signatures made by a keypair with a given
fingerprint as git references. References can be fetched from and
pushed to a remote.

```
$ git signify pull origin
$ git signify push origin
```

Verification can be done with `git signify verify`. For example, to
verify a release of `git-signify` itself:

```
$ git pull --tags
$ git signify pull
$ git signify verify -k <(curl -sfL https://gandas.us.to/keys/git.pub) v0.7.0
$ git signify verify -k <(curl -sfL https://gandas.us.to/keys/git_minisign.pub) v0.7.0
```

To sign git revisions, run something akin to:

```
$ git signify sign -k <secret-key> v0.7.0
```

## In-depth

### Brief overview of how this program works

`git-signify` writes a tree object to some git repository containing the
following blobs:

```
100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	algorithm
100644 blob bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	signature
100644 blob cccccccccccccccccccccccccccccccccccccccc	version
```

Another git object `object` may be present in the tree, if a signature
over a blob or another tree is being made. This `object` is a pointer
to the respective git object being signed over. On the other hand,
`signature` contains the base64 encoded `signify` or `minisign` signature
over the raw (20 byte) id of `object`. The remaining blobs, `version` and
`algorithm`, represent the current version of the `git-signify` tree format
and the algorithm (`minisign` or `signify`) being used, respectively.

The tree is then committed along with a potential parent, which is the commit
hash being signed over, if any. The resulting commit's hash is returned by
`git signify raw sign`.

Signatures end up in `refs/signify/signatures/${key_fingerprint}/${sig_hash}`,
where `$key_fingerprint` can be computed by `git signify fingerprint`, and
`$sig_hash` is a hash returned by `git signify raw sign`.
