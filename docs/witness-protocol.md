# Git Checkpoint Witness Protocol

This document describes a synchronous HTTP-based protocol to obtain [cosignatures][] from Git branch checkpoint witnesses.

[cosignatures]: https://c2sp.org/tlog-cosignature
[checkpoint]: ../README.md#checkpoint-format
[note]: https://c2sp.org/signed-note@v1.0.0

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Introduction

This protocol allows clients (typically Git repositories or deployment pipelines) to obtain cosignatures from witnesses, ensuring that branch references move strictly forward. When creating a new checkpoint for a branch, the client reaches out to witnesses to request cosignatures, providing a cryptographic ancestry proof. Witnesses verify that the checkpoint is a direct descendant of their previously recorded state for that branch, and return a timestamped cosignature.

A witness is an entity exposing an HTTP service identified by a name and a public key. Each witness is configured with a list of supported origin public keys. For each unique repository branch (identified by the `origin` and `ref` in the checkpoint), the witness stores and tracks the latest commit hash it has cosigned.

Only authorized clients (e.g., origin repository administrators or CI systems) are expected to communicate directly with the witnesses. There is no authentication of requests beyond the validation of the signature on the checkpoint itself.

## Relationship and Differences from Merkle Tree Log Witnesses

The Git Checkpoint Witness Protocol is designed to be conceptually equivalent to standard Merkle tree log witness protocols (such as C2SP `tlog-witness.md`), while tailoring the cryptographic objects and state transition validation mechanics to Git's native structures.

### Structural Equivalence

Both protocols enforce that the target state moves strictly forward without requiring the witness to store a copy of the log's tree or the Git repository:

* **Log Witnesses:** Use **Merkle Consistency Proofs** (a list of cryptographic hashes) to verify that a previous log size $M$ is a prefix of a new log size $N$.
* **Git Witnesses:** Use **Git Commit Chains** (a list of raw Git commit objects) to verify that a previous commit $C$ is an ancestor of a new commit $E$.

In both cases, the witness can verify the entire append-only state transition completely offline and statelessly by hashing the provided proof objects.

### Operational Differences

While conceptually equivalent, Git's DAG structure leads to different operational behaviors:

1. **Self-Authenticating Objects:** In a Merkle log, consistency proofs are generated specifically for verification. In Git, the commit objects themselves are the proof; they contain parent pointers natively and are uniquely identified by their cryptographic hashes.
2. **Seamless Fast-Forwards (No 409 Conflict on Stale Client Tracking):** In a standard Merkle log witness, if the witness is "ahead" of the client's local tracker (due to a previous lost response), the mismatch in the requested `old size` triggers a `409 Conflict`. The client must then fetch the witness's actual state, generate a new consistency proof, and retry.
   In Git-Ratchet, the client provides a continuous commit chain spanning from its own last known checkpoint to the new commit tip. If the witness is ahead of the client's tracking (but still on the valid fast-forward path), the witness's actual stored commit naturally exists as a node *within* the provided commit chain. The witness can therefore verify and fast-forward directly from its actual current state to the new tip in a single round-trip, completing with `200 OK` and avoiding any need for client-side conflict retries.

## HTTP Interface

A witness is defined by a name, a public key, and by a submission prefix URL.

### add-checkpoint

The `add-checkpoint` call is used to submit a new Git branch checkpoint to the witness, along with an ancestry proof showing that the new commit descends from the previously cosigned commit tip.

    POST <submission prefix>/add-checkpoint

The request MUST be an HTTP POST. Clients SHOULD use, and witnesses SHOULD support, HTTP keep-alive connections to reduce latency and connection establishment overhead.

The request body MUST be a sequence of:
* Zero or more base64-encoded raw Git commit objects (proving ancestry),
* An empty line,
* The raw [checkpoint][] signed note.

Each ancestry proof line MUST encode a raw Git commit object in base64, terminating in a newline character (U+000A). The set of commit objects provided MUST represent a valid chain of parent-child relationships linking the commit in the checkpoint back to the witness's previously stored commit hash.

For merge commits, the client only needs to include commit objects representing the path from the new tip back to the old commit.

Example request body:

```text
Y29tbWl0IDIyNAp0cmVlIDZhY2Qz...
Y29tbWl0IDIyNQp0cmVlIDhmZmQ1...

example.com/repo refs/heads/main
8db5a2d0eb50ebc5c6439e6a0ae296d11f99c857

— example-origin+a1b2c3d4 qS3fPj...
```

## Witness Verification Logic

Upon receiving a `POST /add-checkpoint` request, the witness MUST perform the following checks:

1. **Checkpoint Parsing:** Parse the signed note checkpoint. Verify that the format is valid and matches the `origin refs/heads/<branch>\n<commit-hash>` template.
2. **Signature Verification:** Check the origin signature against the configured trusted origin public key for the given `origin` identifier. If the signature is invalid, return `403 Forbidden`.
3. **Repository State Lookup:** Look up the stored commit hash for the repository branch (`<origin>/<ref>`).
4. **Consistency / Ancestry Verification:**
   * If the new commit in the checkpoint matches the witness's stored commit, return `200 OK` along with the existing/new cosignature.
   * If the stored commit is empty (uninitialized branch):
     * The witness accepts the new commit directly, updates its stored state, and returns `200 OK` with the cosignature. (No commit chain is required or verified for initializations).
   * If the stored commit is present and differs from the new checkpoint commit:
     * **Decoded Object Validation:**
       * For each base64-encoded commit object in the request, decode it and verify that its cryptographic hash matches its expected commit ID. If any commit object is malformed or does not hash correctly, return `422 Unprocessable Entity`.
     * **Ancestry Traversal:**
       * Start at the new checkpoint commit tip and traverse backward through parent linkages using the provided set of decoded commit objects.
       * If the witness's stored commit is successfully reached along this path, the verification succeeds.
       * If the traversal stops (reaches a commit whose parent object is missing from the request payload) before encountering the stored commit, return `422 Unprocessable Entity`.
5. **State Update:** Update the stored commit hash for the branch to the new commit tip.
6. **Signing:** Generate and return a cosignature line over the checkpoint.

## HTTP Response Codes

| Status Code | Description / Meaning |
| :--- | :--- |
| **200 OK** | The checkpoint is verified, the witness's stored state is updated, and the cosignature is returned in the response body. |
| **400 Bad Request** | The request body is malformed or invalidly formatted. |
| **403 Forbidden** | The origin signature does not verify against the configured trusted public key. |
| **404 Not Found** | The repository origin is unknown or unauthorized on this witness. |
| **422 Unprocessable Entity** | The provided ancestry proof (commit chain) is broken, incomplete, contains invalid/malformed objects, or fails to connect the new tip back to the witness's stored commit. |

### Success Response Format (200 OK)

The response body MUST consist of one or more note signature lines (using the `— ` prefix), terminating in a newline:

```text
— witness-name+e5f6a7b8 base64-encoded-signature-and-timestamp
```
