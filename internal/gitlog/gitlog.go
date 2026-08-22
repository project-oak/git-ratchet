// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gitlog stores a git-ratchet transparency log inside the Git
// repository it describes, as a commit under refs/ratchet/log.
//
// Layout of the log commit's tree:
//
//	checkpoint            latest cosigned tlog-checkpoint
//	tile/entries/<path>   entry bundles, 256 entries each
//
// Entry bundles use the tlog-tiles paths and encoding, via the reference
// implementation in tessera/api, so a tlog-tiles client can read them.
//
// Hash tiles are not stored: every consumer of a git-ratchet log already has
// the whole log locally (it arrives with the repository), and a witness is
// sent its consistency proof in the request, so the tree is recomputed from
// the entries rather than served from tiles.
//
// Storing the log as a commit rather than a blob buys one thing for free: the
// log ref can only be advanced by a fast-forward push, so an ordinary Git
// server rejects a rewritten log before any git-ratchet code runs.
package gitlog

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// LogRef is the ref holding the transparency log.
const LogRef = "refs/ratchet/log"

// EntriesPerBundle is the number of log entries in a full entry bundle.
const EntriesPerBundle = layout.EntryBundleWidth

// checkpointPath is where the cosigned checkpoint lives in the log tree.
const checkpointPath = layout.CheckpointPath

// entriesPrefix is the tlog-tiles directory holding entry bundles. Paths below
// it are produced and parsed by the layout package.
const entriesPrefix = "tile/entries/"

// Log is an in-memory view of the repository's transparency log.
type Log struct {
	repoDir string

	entries    []Entry
	checkpoint string // cosigned checkpoint as stored, empty if the log is new
	head       string // log commit hash, empty if the ref does not exist yet
}

// Open reads the log from the repository. A repository with no log ref yet
// opens as an empty log.
func Open(repoDir string) (*Log, error) {
	l := &Log{repoDir: repoDir}

	if !gitutil.RefExists(repoDir, LogRef) {
		return l, nil
	}

	head, err := gitutil.ResolveRef(repoDir, LogRef)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", LogRef, err)
	}
	l.head = head

	if cp, err := gitutil.CatFile(repoDir, LogRef+":"+checkpointPath); err == nil {
		l.checkpoint = cp
	}

	entries, err := readEntries(repoDir)
	if err != nil {
		return nil, err
	}
	l.entries = entries
	return l, nil
}

// readEntries loads every entry bundle in the log tree, in index order.
func readEntries(repoDir string) ([]Entry, error) {
	out, err := gitutil.Run(repoDir, "ls-tree", "-r", "--name-only", LogRef, entriesPrefix)
	if err != nil {
		// A log with a checkpoint but no entries is not valid, but an empty
		// tree is not an error to read.
		return nil, nil
	}

	// Collect bundle paths keyed by their starting entry index so they can be
	// concatenated in order regardless of how ls-tree sorts them.
	bundles := make(map[uint64]string)
	for _, path := range strings.Split(strings.TrimSpace(out), "\n") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		index, ok := strings.CutPrefix(path, entriesPrefix)
		if !ok {
			return nil, fmt.Errorf("unexpected object in log tree: %q", path)
		}
		n, _, err := layout.ParseTileIndexPartial(index)
		if err != nil {
			return nil, fmt.Errorf("unexpected object in log tree %q: %w", path, err)
		}
		if prev, dup := bundles[n]; dup {
			return nil, fmt.Errorf("log tree has two bundles for index %d: %q and %q", n, prev, path)
		}
		bundles[n] = path
	}

	var entries []Entry
	for i := uint64(0); i < uint64(len(bundles)); i++ {
		path, ok := bundles[i]
		if !ok {
			return nil, fmt.Errorf("log tree is missing entry bundle %d", i)
		}
		content, err := gitutil.CatFile(repoDir, LogRef+":"+path)
		if err != nil {
			return nil, fmt.Errorf("reading entry bundle %s: %w", path, err)
		}
		// Decoding with the tlog-tiles reference implementation rather than a
		// local one keeps the stored bundles honest about the format they
		// claim to be in.
		var bundle api.EntryBundle
		if err := bundle.UnmarshalText([]byte(content)); err != nil {
			return nil, fmt.Errorf("decoding entry bundle %s: %w", path, err)
		}
		for _, raw := range bundle.Entries {
			e, err := ParseEntry(raw)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
}

// marshalBundle encodes entries in the tlog-tiles entry bundle format: each
// entry prefixed with its big-endian uint16 length.
func marshalBundle(entries []Entry) ([]byte, error) {
	var buf []byte
	for _, e := range entries {
		if len(e.raw) > MaxEntrySize {
			return nil, fmt.Errorf("entry is %d bytes, exceeding the %d-byte limit", len(e.raw), MaxEntrySize)
		}
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(e.raw)))
		buf = append(buf, e.raw...)
	}
	return buf, nil
}

// Size is the number of entries in the log, which is also the tree size the
// checkpoint commits to.
func (l *Log) Size() int { return len(l.entries) }

// Entries returns the log's entries in order.
func (l *Log) Entries() []Entry { return l.entries }

// StoredCheckpoint returns the cosigned checkpoint currently in the log,
// or the empty string if the log has never been checkpointed.
func (l *Log) StoredCheckpoint() string { return l.checkpoint }

// Head returns the log's commit hash, or the empty string for a new log.
func (l *Log) Head() string { return l.head }

// LeafHashes returns the leaf hash of every entry, in order.
func (l *Log) LeafHashes() []tlog.Hash {
	hashes := make([]tlog.Hash, len(l.entries))
	for i, e := range l.entries {
		hashes[i] = e.LeafHash()
	}
	return hashes
}

// Root returns the Merkle tree hash over all entries.
func (l *Log) Root() tlog.Hash {
	return tlog.Root(l.LeafHashes())
}

// RootAt returns the Merkle tree hash over the first n entries.
func (l *Log) RootAt(n int) (tlog.Hash, error) {
	if n < 0 || n > len(l.entries) {
		return tlog.Hash{}, fmt.Errorf("tree size %d out of range for log of size %d", n, len(l.entries))
	}
	return tlog.Root(l.LeafHashes()[:n]), nil
}

// Append adds an entry to the in-memory log. Call Save to persist it.
func (l *Log) Append(e Entry) {
	l.entries = append(l.entries, e)
}

// RefRecords returns the decoded ref-record entries naming a ref, in log
// order. Entries of any other type, including types this implementation does
// not recognise, are not included.
func (l *Log) RefRecords(ref string) ([]RefRecord, error) {
	var out []RefRecord
	for i, e := range l.entries {
		if e.Type != TypeRefRecord {
			continue
		}
		rr, err := e.AsRefRecord()
		if err != nil {
			return nil, fmt.Errorf("log entry %d: %w", i, err)
		}
		if rr.Ref == ref {
			out = append(out, rr)
		}
	}
	return out, nil
}

// ConsistencyProofFrom returns the proof that the log at size m is a prefix of
// the log as it currently stands.
func (l *Log) ConsistencyProofFrom(m int) ([]tlog.Hash, error) {
	return tlog.ConsistencyProof(l.LeafHashes(), m)
}

// InclusionProof returns the audit path for the entry at index i.
func (l *Log) InclusionProof(i int) ([]tlog.Hash, error) {
	return tlog.InclusionProof(l.LeafHashes(), i)
}

// Save writes the log's entries and the given cosigned checkpoint as a new
// commit on the log ref.
//
// The update is compare-and-swap against the head observed at Open time, so a
// log that moved underneath a concurrent checkpointer fails rather than
// silently discarding the other writer's entries.
func (l *Log) Save(checkpoint, message string) error {
	blobs := map[string]string{}

	cpBlob, err := gitutil.HashObject(l.repoDir, checkpoint)
	if err != nil {
		return fmt.Errorf("writing checkpoint blob: %w", err)
	}
	blobs[checkpointPath] = cpBlob

	// Rebuild every bundle from the full entry list rather than patching the
	// previous tree. Identical bundles hash to the objects already in the
	// database, so full bundles cost nothing to rewrite, and no superseded
	// partial-bundle path can survive into the new tree.
	for start := 0; start < len(l.entries); start += EntriesPerBundle {
		end := min(start+EntriesPerBundle, len(l.entries))

		content, err := marshalBundle(l.entries[start:end])
		if err != nil {
			return err
		}
		blob, err := gitutil.HashObject(l.repoDir, string(content))
		if err != nil {
			return fmt.Errorf("writing entry bundle: %w", err)
		}
		// A full bundle takes the unsuffixed path; a partial one carries its
		// width, so it never occupies the path its eventual full form will use.
		partial := uint8(0)
		if end-start < EntriesPerBundle {
			partial = uint8(end - start)
		}
		blobs[layout.EntriesPath(uint64(start/EntriesPerBundle), partial)] = blob
	}

	tree, err := l.writeTree(blobs)
	if err != nil {
		return err
	}

	commit, err := l.commitTree(tree, message)
	if err != nil {
		return err
	}

	// update-ref's compare-and-swap form takes the expected old value; the
	// empty string means "the ref must not exist".
	if _, err := gitutil.Run(l.repoDir, "update-ref", LogRef, commit, l.head); err != nil {
		return fmt.Errorf("updating %s (the log may have been advanced concurrently): %w", LogRef, err)
	}
	l.head = commit
	l.checkpoint = checkpoint
	return nil
}

// writeTree builds a tree object from a path-to-blob mapping, using a scratch
// index so the caller's working tree and index are untouched.
func (l *Log) writeTree(blobs map[string]string) (string, error) {
	dir, err := os.MkdirTemp("", "git-ratchet-log-index")
	if err != nil {
		return "", fmt.Errorf("creating scratch index: %w", err)
	}
	defer os.RemoveAll(dir)
	env := []string{"GIT_INDEX_FILE=" + filepath.Join(dir, "index")}

	for path, blob := range blobs {
		if _, err := gitutil.RunWithEnv(l.repoDir, env,
			"update-index", "--add", "--cacheinfo", "100644,"+blob+","+path); err != nil {
			return "", fmt.Errorf("adding %s to log tree: %w", path, err)
		}
	}

	tree, err := gitutil.RunWithEnv(l.repoDir, env, "write-tree")
	if err != nil {
		return "", fmt.Errorf("writing log tree: %w", err)
	}
	return strings.TrimSpace(tree), nil
}

// commitTree creates the log commit, chaining it to the previous log head.
func (l *Log) commitTree(tree, message string) (string, error) {
	args := []string{"commit-tree", tree}
	if l.head != "" {
		args = append(args, "-p", l.head)
	}
	args = append(args, "-m", message)

	// The log commit is machine-generated bookkeeping, so it is attributed to
	// git-ratchet rather than to whoever happens to be running the command.
	// This also means the command works in a repository with no user identity
	// configured, which is the normal situation in CI.
	env := []string{
		"GIT_AUTHOR_NAME=git-ratchet",
		"GIT_AUTHOR_EMAIL=git-ratchet@localhost",
		"GIT_COMMITTER_NAME=git-ratchet",
		"GIT_COMMITTER_EMAIL=git-ratchet@localhost",
	}
	commit, err := gitutil.RunWithEnv(l.repoDir, env, args...)
	if err != nil {
		return "", fmt.Errorf("creating log commit: %w", err)
	}
	return strings.TrimSpace(commit), nil
}
