# git-signify

A tool to sign arbitrary objects in a git repository.

## Generating keys

Signing keys can be generated with [`signify`](https://man.openbsd.org/signify.1),
from the OpenBSD project.

```
$ signify -G -p newkey.pub -s newkey.sec
```

If you do not wish to encrypt your keys, pass the `-n` flag to the
command line of `signify`.

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
$ git signify verify -k <(curl -sfL https://gandas.us.to/keys/git.pub) v0.3.0
```

To sign git revisions, run something akin to:

```
$ git signify sign -k <secret-key> v0.3.0
```

## In-depth

### Brief overview of this program works

`git-signify` writes a tree object to some git repository containing the
following blobs:

```
100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	object
100644 blob bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	signature
```

Where `object` stores the raw (20 byte) object id of some git object
to be signed, and `signature` stores the signature over `object`. The
tree's hash is returned by `git signify sign`.

### Storing signatures in tags

To store signatures in tags, one must use the "raw" mode of `git-signify`.
The raw flags supported by this program and their respective documentation
can be checked by running the following commands:

```
$ git signify raw -h
$ git signify raw sign -h
$ git signify raw verify -h
```

The suggested approach to store signatures in tags is the following:

```
$ SIGNATURE_TREE=$(git signify sign -k $SECRET_KEY $OBJECT_TO_SIGN)
$ SIGNATURE_COMMIT=$(git commit-tree $SIGNATURE_TREE -m Signature)
$ git tag signature-$OBJECT_TO_SIGN $SIGNATURE_COMMIT
$ git push --tags
```

Verification can then be done with:

```
$ git signify raw verify -p -k $PUBLIC_KEY $SIGNATURE_COMMIT^{tree}
```
