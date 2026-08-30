# Transparency log mode

This document specifies `tlog` mode: an alternative to git-ratchet's default
[git-checkpoint](git-checkpoint.md) format in which the repository maintains a
[Merkle transparency log][tlog-tiles] of its own ref updates, stored in the
repository as Git refs, and checkpointed with a standard
[tlog-checkpoint][] cosigned by standard [tlog-witness][] witnesses.

Both modes are available. Select one with `--mode`:

```
git-ratchet log        --mode tlog ...
git-ratchet checkpoint --mode tlog ...
git-ratchet verify     --mode tlog ...
git-ratchet audit      --mode tlog ...
witness                -mode tlog ...
```

`log` exists only in this mode: it is what grows the transparency log. In
`git-checkpoint` mode there is no log, and a checkpoint covers a single ref, so
`checkpoint` takes `--ref` there and rejects it here. Each command says so
rather than quietly doing the other thing.

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

In `git-checkpoint` mode the witness verifies Git commit ancestry, so it will
not cosign a rollback. Doing that requires a witness specification of
git-ratchet's own: an operator can only witness a git-ratchet repository by
running git-ratchet's witness. The security of a ratchet rests on witness
diversity, and a bespoke specification is an obstacle to it.

`tlog` mode removes that obstacle. The checkpoint is an ordinary
`tlog-checkpoint` and the witness call is an ordinary `tlog-witness`
`add-checkpoint`, so any conforming witness can cosign a git-ratchet log
without knowing what Git is.

The ratchet is enforced in both modes. What changes is where: see
[Security properties](#security-properties).

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

An entry is an opaque byte string as far as the log is concerned, so a type may
define as many lines as it needs.

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

There is no timestamp. The origin chooses entry contents, so an
origin-supplied time is an assertion nobody can check, and the witness
cosignatures already carry timestamps from parties that are not the origin.

#### Canonical encoding

Leaf hashes are [RFC 6962][]'s, over the entry's bytes exactly as stored; the
bundle framing is not hashed.

The grammar admits exactly one byte string per statement, so the same statement
always produces the same leaf. Implementations MUST reject an entry that
deviates from it:

- every line, including the last, is terminated by a single `\n`;
- no carriage returns anywhere;
- no leading or trailing whitespace on any line;
- exactly one space between fields on a line;
- hex is lowercase;
- the type line is non-empty and contains no whitespace.

Two encoders that disagreed about, say, a trailing space would produce
different leaves for the same statement.

[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

### Evolution

The version is part of the type identifier: `ref-record/v1` is one string, not
a name and a version field. A change in what a statement means produces a new
type identifier.

**Entries of an unrecognised type are skipped.** An implementation reading a
type it does not know ignores that entry and carries on.

Skipping is safe in one direction only. Verification does not just read the
log; it reconciles the log against the repository. An implementation that skips entries has an idea of the
latest logged state that lags the real ref, and a ref ahead of the log is
already a failure. So skipping can make verification fail where a newer
implementation would have passed, but it cannot make it pass where a newer one
would have failed.

New types may therefore only ever *widen* the set of ref-to-commit mappings a
verifier accepts, never narrow it. A type that withdrew something previously
recorded — a revocation — widens the set, so it can be added later: an
implementation predating it fails closed on the repository that used it, and
the relying party upgrades. A type that narrowed the set could not be added
this way, because implementations predating it would skip it and accept what it
was meant to rule out.

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

There is no ref path, no Git object hash, and no other Git-specific field,
which is what makes the checkpoint cosignable by a witness that has never heard
of git-ratchet.

Witnesses append [tlog-cosignature][] lines.

### Signature algorithms

Signatures follow [signed-note][] and [tlog-cosignature][], and are produced and
verified by [transparency-dev/formats][formats].

One consequence is specific to this mode. signed-note assigns `0x06` to
timestamped ML-DSA-44 (sub)tree cosignatures and assigns nothing to a plain
ML-DSA-44 signature over a note's text, so an ML-DSA-44 signature is always the
`cosigned_message` construction, including when the signer is the log. That
construction names a log origin, a leaf range and a Merkle root, so it is
defined only over a tlog-checkpoint. ML-DSA-44 keys therefore work in this mode
and not in `git-checkpoint` mode, whose notes have no such fields;
`git-checkpoint` mode is Ed25519-only.

[formats]: https://github.com/transparency-dev/formats

### Storage

The log lives at `refs/ratchet/log`, which points at a **commit**. Each `log` or
`checkpoint` run adds one commit whose tree is:

```
checkpoint            the cosigned tlog-checkpoint
tile/entries/<path>   entry bundles, 256 entries each
```

Bundle paths and encoding are [tlog-tiles][]'s, via the reference
implementation in `tessera/api`, so a tlog-tiles client can read these bundles
directly. Entries are opaque byte strings of at most 65535 bytes.

Two practical consequences. The bundle framing contains NUL bytes, so Git treats
bundle blobs as binary: `git log -p` on the log ref reports "Binary files
differ" rather than showing added entries, though `git cat-file -p` prints them
and the entries themselves are plain text. And storing the log as a commit
means the log ref can only be advanced by a fast-forward push, so an ordinary
Git server rejects a rewritten log before any git-ratchet code runs — not a
security control, since a server under the origin's control can be told to
accept a force-push, but it costs nothing.

#### Hash tiles are not stored

A conforming tlog-tiles log also serves hash tiles under `tile/<level>/<path>`.
This implementation does not write them, and recomputes the tree from the
entries instead.

Hash tiles exist so that a client holding none of the log can verify a proof
against it. Every consumer of a git-ratchet log holds all of it, since the log
is contained by the repository, and the witness is sent its consistency proof
in the request. Emitting them would be a small addition if a third-party
tlog-tiles client wanted to consume the log directly.

## Policy

`tlog` mode reads a [tlog-policy][] file, parsed and evaluated by
`transparency-dev/formats/policy`:

```
log <vkey> [<url>]
witness <name> <vkey> [<url>]
group <name> <all|any|k> <member>...
quorum <name|none>
```

Note the field order: the vkey precedes the optional URL. The policy parser
`git-checkpoint` mode uses puts the URL first, so **a policy file serves one
mode or the other**, not both. Aligning `git-checkpoint` mode would break
policy files already deployed, so it keeps its own parser until that is worth
doing on its own terms.

Application-specific URL schemes pass through untouched, so a
`github-issue://owner/repo` witness is accepted.

The log signature and the witness quorum are both evaluated by the formats
package, using the constructions in [Signature algorithms](#signature-algorithms)
above. git-ratchet adds no rules of its own. A policy MAY declare more than one
log, in which case a checkpoint is accepted if it is signed by any of them and
satisfies the quorum; git-ratchet writes policies with one, but nothing here
depends on that.

[tlog-policy]: https://c2sp.org/tlog-policy

## Witnessing

`tlog` mode is a [tlog-witness][] *client*. It submits `add-checkpoint` requests
and collects [cosignatures][tlog-cosignature]; it does not implement a witness.

A `tlog-checkpoint` names an origin, a tree size and a root hash and nothing
else, so any witness on the existing network can cosign one without knowing
what a Git ref is. A `git-checkpoint` needs a witness that understands commit
ancestry, which is why `git-checkpoint` mode provides one. A checkpoint here
also carries nothing repository-specific, so a private repository can use
public witnesses without disclosing anything about its contents.

The client is [transparency-dev/witness][witness-impl]'s, and the tests run
against that project's witness implementation. Both halves being ours would let
a mistake in one agree with the same mistake in the other.

### Witnesses reached by other transports

`checkpoint --mode tlog` contacts every witness in the policy itself, whatever
carries it. A witness reached over HTTP is a POST; a
[GitHub Issue witness](github-issue-witness.md) is an issue and a comment.

The carrier is an `http.RoundTripper` registered for the witness's URL scheme,
so the code that submits a checkpoint does not know which one it got. Only the
delivery differs: the messages are the `add-checkpoint` request and response,
and the witness is `transparency-dev/witness`, so every rule in
[tlog-witness][] applies unchanged — including the ratchet, which is why
`--stored-checkpoint` is required of a GitHub Issue witness rather than
optional as it is in `git-checkpoint` mode.

A witness that holds a different tree size answers 409 with the size it does
hold, and the client regenerates its consistency proof from there and resubmits
once. `git-checkpoint` mode avoids that round trip by sending a commit chain
spanning any gap; a consistency proof is anchored to a specific size, so the
recovery costs one extra request.

The witness never sees the entries. It cannot tell a fast-forward from a
rollback, and it is not asked to — [Verification](#verification) is where that
is established.

[witness-impl]: https://github.com/transparency-dev/witness

## Logging and checkpointing

Growing the log and checkpointing it are separate commands, as they are for any
transparency log. `log` records ref states. `checkpoint` commits, with
witnesses, to the current contents of the log.

`log` is local, needs no key and contacts nobody; `checkpoint` needs the origin
key and a quorum of witnesses over the network. `log` takes any number of refs;
`checkpoint` takes none, covering the whole log. A failure to reach a witness
leaves logged entries where they are, to be covered by the next checkpoint,
rather than discarding them.

`git-ratchet log --mode tlog --ref R...` performs, in order:

1. For each ref, resolve it and append a `ref-record` naming the object it
   points at, unless the ref's latest entry already names that object.
2. **Walk the chain of every ref in the log**, including the entries just
   appended. A branch's entries MUST each descend from the one before; a tag
   MUST NOT be logged at more than one object. If not, refuse.
3. Write the entries as one commit on the log ref, carrying the stored
   checkpoint forward unchanged.

`git-ratchet checkpoint --mode tlog` performs, in order:

1. Refuse an empty log.
2. **Walk the chain of every ref in the log**, as above.
3. Build and sign the `tlog-checkpoint` over the log's current head, collect
   cosignatures, and require the policy's quorum.
4. Write the checkpoint as one commit on the log ref.

### The chain walks here are not security controls

Neither walk defends against an attacker. They stop an operator destroying
their own ref by accident. An attacker who can write to `refs/ratchet/log`
pushes entries straight to the ref and never runs either command; removing both
walks would not change what the mode guarantees. That comes from
[Verification](#verification).

A cosigned entry cannot be taken back: it is in the prefix of every later
checkpoint, verification walks a ref's entries from the start, and no statement
withdraws one. An entry that breaks the chain makes its ref unverifiable
permanently — new origin key, history restarts. The ordinary way to produce one
is not an attack: it is someone force-pushing a branch and then running `log`.

The walks are therefore placed at the two points where the entry can still be
withdrawn:

- `log` walks before writing. The refusal costs nothing: the log ref has not
  moved, so the branch can be put back and the run retried.
- `checkpoint` walks again before seeking cosignatures, because entries can
  reach the log ref without going through `log` — a direct push, an older
  version of this tool, another implementation. An entry that has not been
  cosigned can still be dropped by resetting the log ref to its last
  checkpointed commit; one that has been cannot.

Both walks cover every ref in the log, not only the refs being recorded. A
break in another ref's chain is already fatal for that ref; extending the log
over it buries it deeper, and the operator running the tool today is the one in
a position to notice.

A conforming implementation MAY omit both walks. `verify` MUST NOT rely on them
having happened.

## Verification

`git-ratchet verify --mode tlog` performs, in order:

1. Read `refs/ratchet/log` and its stored checkpoint, and verify it against the
   policy: it MUST carry an origin line and signature matching one of the
   policy's logs, and MUST satisfy the quorum.
2. Take **the log the checkpoint commits to**: the first `size` entries, where
   `size` is the checkpoint's tree size. Their root hash MUST equal the
   checkpoint's.
3. **Walk the ref-record entries for each requested ref**, in log order.
   Entries of any other type, including unrecognised ones, are skipped. Runs of
   consecutive entries naming the same object are first collapsed to one: an
   entry that repeats a ref's current logged state says nothing new, so it MUST
   NOT be read as a second statement about the ref. The rules then apply to
   what is left:
   - **Branches**: each logged commit MUST be a descendant of the one logged
     before it. A break means history was rewritten.
   - **Tags**: a tag MUST NOT be logged at more than one object. A later
     entry naming a different object is a move.
4. Compare the ref's current value against its latest entry there: a
   branch MUST be an ancestor of it or equal to it, a tag MUST match it exactly.

### The checkpointed prefix

An entry is bytes in a Git tree until a cosigned checkpoint commits to it.
Anyone who can push to `refs/ratchet/log` can append; only the tree the quorum
signed means anything, and a checkpoint of size `size` covers entries `[0,
size)` and no others.

Verification therefore reads that prefix and nothing else. Entries beyond it are
ignored rather than refused: they are evidence of nothing, and refusing them
would let anyone with push access to the log ref break verification for every
ref, including ones they never touched. Ignoring them costs nothing, because a
ref that the unwitnessed entries would have vouched for is no longer an ancestor
of the latest witnessed entry, and step 4 rejects it.

The reverse is an error. A log holding *fewer* entries than the checkpoint
commits to cannot reproduce the tree a quorum signed, which means witnessed
entries were removed.

Verification reads only the refs it was asked about. A log ref carrying
unwitnessed entries is not reported.

Step 3 is the ratchet. It replaces what the witness does in `git-checkpoint`
mode, and it is always performed. It MUST NOT be skipped on the grounds that
`log` or `checkpoint` already applied the same rule: a verifier cannot know
whether they ran, and an attacker writing to the log ref would not have run
them.

The walk does more work than `git-checkpoint` mode's `verify` but is still
cheap. The log and the commit objects are in the same repository, so it is a
sequence of local `git merge-base --is-ancestor` calls with nothing to fetch.

If a logged commit is missing from the object database — because a rollback was
followed by garbage collection — the walk fails with a diagnostic saying so.
That is the correct outcome: the log asserts a commit existed and the
repository cannot produce it.

## Security properties

Both modes give the same guarantee, and in both a relying party establishes it
by running `verify`. They differ in where the ratchet is enforced, and so in
how much `verify` has to do.

| | `git-checkpoint` | `tlog` |
| :--- | :--- | :--- |
| Witness verifies | Git commit ancestry | Merkle tree consistency |
| Witness can cosign a rollback | No | Yes |
| A rollback is refused by | The witness, at cosigning time | `verify`, at verification time |
| `verify` does | O(1): checks one signed note | O(entries for the ref): walks the log |
| Usable with third-party witnesses | No | Yes |
| Checkpoint meaningful standalone | Yes — asserts a ref is at a commit | No — asserts only a log's head |

`log` and `checkpoint` also refuse to record a rewrite. They are absent from
that table because they protect the operator, not the relying party: see
[The chain walks here are not security controls](#the-chain-walks-here-are-not-security-controls).

Three consequences:

**A witness will cosign a rollback.** Appending a rolled-back state to a log is
a consistent log operation, and a witness that sees only tree heads has no
basis to object; nothing in a consistency proof says anything about Git
ancestry. What the witness attests to is that the log is append-only, which is
what makes a rollback, once recorded, undeniable.

**`verify` does the ancestry check itself.** In `git-checkpoint` mode the
witness has done it, so `verify` reads one signed note. Here `verify` walks the
logged entries for the ref. It MUST do so on every run: it cannot know whether
anything checked the log before it, and an attacker writing to the log ref
would not have.

**A checkpoint no longer means anything on its own.** A `git-checkpoint` is a
semantic attestation — *this witness attests `main` is at this commit, having
arrived there by fast-forward* — and can be quoted as evidence by someone who
does not have the repository. A `tlog-checkpoint` attests only that a log is
append-only and its head is this. Anything that consumes checkpoints outside
`git-ratchet verify` — a build attestation referencing one, say — is relying on
a property `tlog` mode does not provide. This is the one respect in which the
two modes are not interchangeable.

Tamper-evidence is unchanged. A rollback that reaches the log is permanent,
cosigned, and undeniable; the log cannot be rewritten to remove it without
losing witness cosignatures.

## Implementation

The Merkle tree comes from [`github.com/transparency-dev/merkle`][merkle],
maintained by the authors of the transparency-log specifications this mode
implements. Consistency verification is what a witness runs to decide whether
to cosign, so a bespoke implementation of it would be a poor trade.

[Tessera][] was considered and not used. Tessera is a log *server* framework —
batching, sequencing, antispam, and storage drivers for GCS, S3, MySQL and
POSIX — and importing its core links 70 non-standard-library packages, against
3 for `merkle/proof`. git-ratchet appends at most one entry per ref per push,
from a CLI, into a Git ref. Almost none of that machinery applies, and adopting
it would mean writing a storage driver whose unit of work is rewriting a Git
tree.

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

- **Hash tiles**, for the reason given above.
- **Concurrency.** A single log serialises writes across all of a repository's
  refs. `log` and `checkpoint` both write the log ref, so two runs of either
  that start from the same log head will race, and the loser's write is
  rejected by a compare-and-swap on the log ref rather than silently discarding
  the winner's entries. Repositories ratcheting more than one ref concurrently
  should serialise the runs — for example with a repository-wide, rather than
  per-ref, CI concurrency group.
