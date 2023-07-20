# git-signify

A tool to sign arbitrary objects in a git repository.

## Brief overview of how it works

This tool writes a tree object to some git repository containing the
following blobs:

```
100644 blob aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa	object
100644 blob bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb	signature
```

Where `object` stores the raw (20 byte) object id of some git object
to be signed, and `signature` stores the signature over `object`. The
tree's hash is returned by `git signify sign`.

## Generating keys

Signing keys can be generated with [`signify`](https://man.openbsd.org/signify.1),
from the OpenBSD project.

```
$ signify -G -p newkey.pub -s newkey.sec
```

If you do not wish to encrypt your keys, pass the `-n` flag to the
command line of `signify`.

## Usage

The flags supported by this program and their respective documentation can
be checked by running the following commands:

```
$ git signify -h
$ git signify sign -h
$ git signify verify -h
```

To push signatures to a remote, the suggested approach is the following:

```
$ SIGNATURE_TREE=$(git signify sign -k $SECRET_KEY $OBJECT_TO_SIGN)
$ SIGNATURE_COMMIT=$(git commit-tree $SIGNATURE_TREE -m Signature)
$ git tag signature-$OBJECT_TO_SIGN $SIGNATURE_COMMIT
$ git push --tags
```

Verification can then be done with:

```
$ git signify verify -p -k $PUBLIC_KEY $SIGNATURE_COMMIT^{tree}
```
