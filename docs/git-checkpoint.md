# git-checkpoint mode (removed)

git-ratchet originally stored a **signed note per ref**. This document records
what that was and why it is gone; the format git-ratchet uses now is specified
in [The transparency log](transparency-log.md).

## What it was

A checkpoint was a [signed note][] whose body bound one ref to one object hash:

```
<origin> <ref>
<object hash>
```

It was signed by the origin, submitted to witnesses over an HTTP protocol of
git-ratchet's own, and stored at `refs/checkpoints/heads/<branch>` or
`refs/checkpoints/tags/<tag>`.

The ratchet was enforced by the witness, at cosigning time. A request carried
an **ancestry proof** — the chain of commit objects from the new commit back to
the one the witness last cosigned — so a witness could verify Git ancestry
without a clone, each commit object being self-authenticating. For a branch the
witness refused to cosign a commit that did not descend from its stored one;
for a tag it refused any object hash but the one it first saw.

## Why it was removed

The witness had to understand Git. Verifying commit ancestry is not something
the [tlog-witness][] protocol does, so witnessing a git-ratchet repository
meant running git-ratchet's own witness implementation, against a specification
only git-ratchet used.

The security of a ratchet rests on witness diversity, and a bespoke protocol is
an obstacle to it. The transparency log gets the same guarantee from a standard
[tlog-checkpoint][] that any conforming witness can cosign without knowing what
Git is. What moves is where the ratchet is enforced: `verify` establishes
ancestry itself, by walking the logged entries locally.

Carrying both meant two policy grammars, two witness protocols, two
verification paths and a `--mode` flag on every subcommand, for one guarantee.

[signed-note]: https://c2sp.org/signed-note@v1.0.0
[tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-witness]: https://c2sp.org/tlog-witness
