# Transparency log mode

This document specifies `tlog` mode: an alternative to git-ratchet's default
[git-checkpoint](git-checkpoint.md) format in which the repository maintains a
[Merkle transparency log][tlog-tiles] of its own ref updates, stored in the
repository as Git refs, and checkpointed with a standard
[tlog-checkpoint][] cosigned by standard [tlog-witness][] witnesses.

Both modes ship. Select one with `--mode`:

```
git-ratchet checkpoint --mode tlog ...
git-ratchet verify     --mode tlog ...
git-ratchet audit      --mode tlog ...
witness                -mode tlog ...
```

`--mode git-checkpoint` is the default and is unchanged.

[tlog-tiles]: https://c2sp.org/tlog-tiles
[tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-witness]: https://c2sp.org/tlog-witness
[tlog-cosignature]: https://c2sp.org/tlog-cosignature
[signed-note]: https://c2sp.org/signed-note

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Why

In `git-checkpoint` mode the witness verifies Git commit ancestry. That makes
the ratchet an *enforced* property — a witness will not cosign a rollback — but
it means every witness must run git-ratchet's own witness implementation. Since
the security of a ratchet rests on witness *diversity*, and diversity requires
witness operators who have no relationship with the origin, requiring bespoke
software to participate is a real obstacle.

`tlog` mode removes that obstacle. The checkpoint is an ordinary
`tlog-checkpoint` and the witness call is an ordinary `tlog-witness`
`add-checkpoint`, so any conforming witness can cosign a git-ratchet log
without knowing what Git is.

The cost is stated plainly in [Security properties](#security-properties)
below: the ratchet stops being enforced at cosigning time and becomes a
property that verifiers establish for themselves.

## The log

Each ratcheted repository has exactly **one** log, covering all of its refs.

One log per repository, rather than one per ref, is a deliberate choice. A
witness's state — and its operator's onboarding process — is per log. A
repository with fifty tags would otherwise need fifty witness registrations,
which defeats the purpose of speaking a protocol third-party witnesses already
implement.

### Entries

An entry is a sequence of newline-terminated lines. The first line names the
type of statement the entry makes; the remaining lines belong to that type:

```
ref-record/v1
refs/heads/main 4f0f30afb02b71590f0b2e0a67f0b846715e1d04
```

Bundles length-prefix entries (see [Storage](#storage)), so an entry is an
opaque byte string as far as the log is concerned. It may contain newlines
freely, and a type may define as many lines as it needs.

#### `ref-record/v1`

States that a ref pointed at an object. Exactly two lines:

```
ref-record/v1
<ref> <object>
```

`<ref>` is a full ref path and MUST begin with `refs/heads/` or `refs/tags/`.
`<object>` is a lowercase hex object hash of 40 characters (SHA-1) or 64
(SHA-256): a commit hash for branches and lightweight tags, the tag object hash
for annotated tags — the same value `git-checkpoint` mode binds.

Entries record **state, not transitions**. An entry does not name the ref's
previous value. The log's ordering already establishes it, and a self-asserted
predecessor would be a field that verification must not trust anyway.

There is deliberately no timestamp. The origin chooses entry contents, so an
origin-supplied time is an assertion nobody can check; the witness cosignatures
already carry timestamps from parties that are not the origin.

#### Canonical encoding

The Merkle leaf hash of an entry is `SHA-256(0x00 || <entry bytes>)`, per
[RFC 6962][] section 2.1, over the entry's bytes exactly as stored — the
bundle's length prefix is framing and is not hashed.

The grammar admits exactly one byte string per statement, so the same statement
always produces the same leaf. Implementations MUST reject an entry that
deviates from it:

- every line, including the last, is terminated by a single `\n`;
- no carriage returns anywhere;
- no leading or trailing whitespace on any line;
- exactly one space between fields on a line;
- hex is lowercase;
- the type line is non-empty and contains no whitespace.

Being tolerant here would defeat the point of the format. Two encoders that
disagree about, say, whether a trailing space is permitted would produce
different bytes for the same statement, and therefore different leaves.

[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

### Evolution

The version is part of the type identifier — `ref-record/v1` is one string, not
a name and a version field — and there is no second version for the framing. A
change in what a statement means produces a new type identifier. The framing
itself, first line names the type and the rest is its payload, is thin enough
that a change to it can be announced the same way.

**Entries of an unrecognised type are skipped.** An implementation reading a
type it does not know ignores that entry and carries on.

This is safe because verification does not merely read the log: it reconciles
the log against the repository. An implementation that skips entries has an
idea of the latest logged state that lags the real ref, and a ref ahead of the
log is already a failure. Skipping cannot turn a bad repository into a good
verdict for any statement that records state.

It would not be safe for a statement that *withdrew* something previously
recorded — skipping that would turn a revocation into silence. Such a statement
cannot be added compatibly later, because every existing implementation would
already skip it. No marker is reserved for one. That is a deliberate trade: the
cost of complicating the format now was judged higher than the likelihood of
ever needing it.

#### Worked example: tombstones

A future extension might record that a commit has been excised from history —
sometimes a legal requirement, and otherwise indistinguishable from the
rewriting this mode exists to detect. It is **not implemented**; it is set out
here to show how the rules above accommodate a new type.

```
tombstone/v1
4f0f30afb02b71590f0b2e0a67f0b846715e1d04 refs/heads/main
removed under a legal request
```

An implementation predating tombstones skips the entry, then walks the
ref-record entries for `refs/heads/main` and finds a commit that does not
descend from its predecessor. It fails, reporting rewritten history. That is
the correct outcome: it cannot tell an authorised excision from an
unauthorised rewrite, so it must not pronounce the repository sound.

An implementation that understands tombstones consults the entry when the walk
reaches the break, and applies whatever policy governs them. Either way the
tombstone is in the log: permanent, cosigned, and undeniable, so the excision
is transparent even though the commit is gone.

Note the multi-line payload with free text. The length-prefixed bundle framing
carries it with no escaping, so a type is not constrained to fit on one line.

### Checkpoint

The log is checkpointed with a [tlog-checkpoint][] body:

```
<origin>
<size>
<base64 root hash>
```

The origin is the same identifier `git-checkpoint` mode uses — the key name
from the origin's [signed-note][] verifier key. The size is the number of
entries. The root hash is the RFC 6962 Merkle tree hash over all entry leaf
hashes.

Note what is *not* here: no ref path, no Git object hash, no Git-specific field
of any kind. That is what makes the checkpoint cosignable by a witness that has
never heard of git-ratchet.

Witnesses append [tlog-cosignature][] lines. For ML-DSA-44 the cosigned message
is the specification's binary struct with its fields carrying their intended
values — `log_origin` is the checkpoint's origin, `end` is the tree size, and
`hash` is the root hash. (In `git-checkpoint` mode there are no such values, so
those fields are filled by repurposing the ref line and object hash; see
`buildCosignedMessage` in `internal/note/note.go`.)

### Storage

The log lives at `refs/ratchet/log`, which points at a **commit**. Each
checkpoint adds one commit whose tree is:

```
checkpoint            the cosigned tlog-checkpoint
tile/entries/<path>   entry bundles, 256 entries each
```

Entry bundles use the tlog-tiles paths and encoding. Paths carry the bundle
index in base-1000 groups of three digits joined by `/`, every group but the
last prefixed with `x`, and a `.p/<width>` suffix while the bundle is not yet
full: bundle 0 is `tile/entries/000` once full and `tile/entries/000.p/17` at
seventeen entries; bundle 1234567 is `tile/entries/x001/x234/567`.

Within a bundle, entries are concatenated, each prefixed with its length as a
big-endian `uint16`. Entries are therefore opaque byte strings, limited to
65535 bytes. Paths and decoding both come from the reference implementation in
`tessera/api`, so a tlog-tiles client can read these bundles directly.

One consequence worth knowing: the length prefixes contain NUL bytes, so Git
treats bundle blobs as binary and `git log -p` on the log ref reports "Binary
files differ" rather than showing added entries. `git cat-file -p` still prints
them, and the entries themselves are plain text.

Storing the log as a commit rather than a blob has a useful consequence: the
log ref can only be advanced by a fast-forward push, so an ordinary Git server
rejects a rewritten log before any git-ratchet code runs. That is a
belt-and-braces check, not a security control — a server under the origin's
control can be told to accept a force-push — but it costs nothing.

#### Hash tiles are not stored

A conforming tlog-tiles log also serves hash tiles under `tile/<level>/<path>`.
This implementation does not write them, and recomputes the tree from the
entries instead.

Hash tiles exist so that a client holding none of the log can verify a proof
against it. Every consumer of a git-ratchet log holds all of it — the log
arrives with the repository — and the witness is sent its consistency proof in
the request and needs no tiles either. Nothing in this design reads them.
Emitting hash tiles would be a small addition if a third-party tlog-tiles
client ever wanted to consume the log directly.

## Witness protocol

`tlog` mode speaks [tlog-witness][] `add-checkpoint`:

    POST <submission prefix>/add-checkpoint

with a request body of:

```
old <size>
<base64 consistency proof hash>
...

<signed tlog-checkpoint note>
```

The witness MUST verify the origin signature, look up the tree it last cosigned
for that origin, and verify the RFC 6962 consistency proof from that tree to
the submitted one. It MUST reject a submission whose size is below the size it
holds.

The witness never sees the entries. It cannot tell a fast-forward from a
rollback, and it is not asked to.

### Response codes

| Status | Meaning |
| :--- | :--- |
| **200 OK** | Consistency verified, state updated, cosignature in the body. |
| **400 Bad Request** | Malformed request or checkpoint body. |
| **403 Forbidden** | Origin signature invalid, or the checkpoint's origin does not match the signer. |
| **404 Not Found** | Origin unknown to this witness. |
| **409 Conflict** | The client's `old` size is not the size the witness holds, or the log would shrink. |
| **422 Unprocessable Entity** | The consistency proof does not verify. |

A 409 body begins with `old <size>` naming the size the witness actually holds.
This implementation's client uses that to regenerate its proof and resubmit
once, automatically.

This is the conflict round trip that `git-checkpoint` mode avoids: a commit
chain spans any gap between client and witness, whereas a consistency proof is
anchored to a specific size. The recovery is a single extra request.

## Verification

`git-ratchet verify --mode tlog` performs, in order:

1. Read `refs/ratchet/log` and its stored checkpoint. Verify the origin
   signature and witness quorum against the policy.
2. Check the checkpoint's origin matches the policy's log name.
3. Check the entries present reproduce the checkpoint's size and root hash
   exactly. Entries beyond the checkpoint are unwitnessed; a mismatch fails.
4. **Walk the ref-record entries for each requested ref**, in log order.
   Entries of any other type, including unrecognised ones, are skipped:
   - **Branches**: each logged commit MUST be a descendant of the one logged
     before it. A break means history was rewritten.
   - **Tags**: a tag MUST appear exactly once. A second entry is a move,
     whatever object it names.
5. Compare the ref's current value against its latest entry: a branch MUST be
   at or behind it, a tag MUST match it exactly.

Step 4 is the ratchet. It replaces what the witness used to do, and it is
always performed — there is no cheaper verification path, because a cheaper
one would not be safe.

The walk is inexpensive despite doing more work than `git-checkpoint` mode's
`verify`. The log and the commit objects are in the same repository, so it is a
sequence of local `git merge-base --is-ancestor` calls with nothing to fetch.

If a logged commit is missing from the object database — because a rollback was
followed by garbage collection — the walk fails with a diagnostic saying so.
That is the correct outcome: the log asserts a commit existed and the
repository cannot produce it.

## Security properties

The two modes protect the same thing and detect the same attacks. They differ
in **who establishes the ratchet**, and the difference is worth being precise
about.

| | `git-checkpoint` | `tlog` |
| :--- | :--- | :--- |
| Witness verifies | Git commit ancestry | Merkle tree consistency |
| Witness can cosign a rollback | No | **Yes** |
| Ratchet established by | The witness, at cosigning time | The verifier, walking the log |
| Verifier work | O(1): check one signed note | O(entries for the ref), all local |
| Usable with third-party witnesses | No | **Yes** |
| Checkpoint meaningful standalone | Yes — asserts a ref is at a commit | No — asserts only a log's head |

Two consequences deserve emphasis:

**A witness will cosign a rollback.** This is not a defect; appending a
rolled-back state to a log is a perfectly consistent log operation, and a
witness that only sees tree heads has no basis to object. The end-to-end test
`TestTlogDetectsBranchRollback` asserts exactly this: the checkpoint succeeds,
and `verify` rejects it.

**A checkpoint no longer means anything on its own.** A `git-checkpoint` is a
semantic attestation — *this witness attests `main` is at this commit, having
arrived there by fast-forward* — and can be quoted as evidence by someone who
does not have the repository. A `tlog-checkpoint` attests only that a log is
append-only and its head is this. Anything that consumes checkpoints outside
`git-ratchet verify` — a build attestation referencing one, say — is relying on
a property `tlog` mode does not provide.

What is *not* weakened is tamper-evidence. A rollback that reaches the log is
permanent, cosigned, and undeniable; the log cannot be rewritten to remove it
without losing witness cosignatures. Detection moves from the witness to the
verifier, and the verifier can do it with what it already has.

## Implementation

The Merkle tree comes from [`github.com/transparency-dev/merkle`][merkle], maintained
by the authors of the transparency-log specifications this mode implements.
Consistency verification is what a witness runs to decide whether to cosign, so
it is not somewhere to carry a bespoke implementation.

[Tessera][] was considered and not used. Tessera is a log *server* framework —
batching, sequencing, antispam, and storage drivers for GCS, S3, MySQL and
POSIX — and importing its core links 70 non-standard-library packages, against
3 for `merkle/proof`. git-ratchet appends at most one entry per push, from a
CLI, into a Git ref. Almost none of that machinery applies, and adopting it
would mean writing a storage driver whose unit of work is rewriting a Git tree.

Entry bundle paths and decoding come from `tessera/api` and `tessera/api/layout`
— 2 packages with no external dependencies, and separable from the Tessera
machinery discussed above. Hand-rolling that layer produced bundles no
tlog-tiles client could read.

`internal/tlog` is a thin adapter over the library. It works in fixed-size hash
values rather than byte slices, and resolves proof nodes from the in-memory
entry list, because the library's proof generation reports which nodes a proof
needs and leaves fetching them to the caller — it is built for logs whose nodes
live in tiled storage, which these do not.

[merkle]: https://github.com/transparency-dev/merkle
[Tessera]: https://github.com/transparency-dev/tessera

## Scope

The following are not implemented in this mode:

- **Decomposed workflow.** `checkpoint-request` and `checkpoint-store` support
  `git-checkpoint` mode only, so the [GitHub Issue witness](github-issue-witness.md)
  transport is not available for `tlog` mode. Only HTTP witnesses are.
- **Hash tiles**, for the reason given above.
- **Concurrency.** A single log serialises checkpointing across all of a
  repository's refs. Two checkpoint runs that start from the same log head will
  race, and the loser's `Save` is rejected by a compare-and-swap on the log ref
  rather than silently discarding the winner's entries. Repositories
  checkpointing more than one ref concurrently should serialise the runs — for
  example with a repository-wide, rather than per-ref, CI concurrency group.
