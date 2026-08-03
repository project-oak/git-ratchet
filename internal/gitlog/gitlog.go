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
// Entry bundles follow the tlog-tiles path scheme, so the entries a third
// party needs to reconstruct the tree are laid out where a tlog-tiles client
// expects them. Hash tiles are not stored: every consumer of a git-ratchet log
// already has the whole log locally (it arrives with the repository), so the
// tree is recomputed from the entries rather than served from tiles.
//
// Storing the log as a commit rather than a blob buys one thing for free: the
// log ref can only be advanced by a fast-forward push, so an ordinary Git
// server rejects a rewritten log before any git-ratchet code runs.
package gitlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// LogRef is the ref holding the transparency log.
const LogRef = "refs/ratchet/log"

// EntriesPerBundle is the number of log entries in a full entry bundle, per
// the tlog-tiles tile height of 8.
const EntriesPerBundle = 256

// checkpointPath is where the cosigned checkpoint lives in the log tree.
const checkpointPath = "checkpoint"

// Entry is a single logged statement: the object a ref pointed at when the
// entry was appended.
//
// Entries record state, not transitions. The log's own ordering establishes
// what the previous state was, so carrying a self-asserted predecessor in the
// entry would add a field that verification must not trust anyway.
type Entry struct {
	Ref  string // full ref path, e.g. "refs/heads/main"
	Hash string // hex object hash the ref pointed at
}

// String renders the entry's canonical form, which is what gets hashed into
// the Merkle tree and written to the entry bundle.
func (e Entry) String() string {
	return e.Ref + " " + e.Hash
}

// LeafHash returns the RFC 6962 leaf hash of the entry.
func (e Entry) LeafHash() tlog.Hash {
	return tlog.HashLeaf([]byte(e.String()))
}

// ParseEntry parses an entry's canonical form.
func ParseEntry(s string) (Entry, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return Entry{}, fmt.Errorf("malformed log entry %q: expected 2 fields, got %d", s, len(fields))
	}
	if _, err := gitutil.ParseRefKind(fields[0]); err != nil {
		return Entry{}, fmt.Errorf("malformed log entry %q: %w", s, err)
	}
	return Entry{Ref: fields[0], Hash: fields[1]}, nil
}

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
	out, err := gitutil.Run(repoDir, "ls-tree", "-r", "--name-only", LogRef, "tile/entries/")
	if err != nil {
		// A log with a checkpoint but no entries is not valid, but an empty
		// tree is not an error to read.
		return nil, nil
	}

	// Collect bundle paths keyed by their starting entry index so they can be
	// concatenated in order regardless of how ls-tree sorts them.
	bundles := make(map[int]string)
	for _, path := range strings.Split(strings.TrimSpace(out), "\n") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		idx, err := parseBundlePath(path)
		if err != nil {
			return nil, fmt.Errorf("unexpected object in log tree: %w", err)
		}
		if prev, dup := bundles[idx]; dup {
			return nil, fmt.Errorf("log tree has two bundles for index %d: %q and %q", idx, prev, path)
		}
		bundles[idx] = path
	}

	var entries []Entry
	for i := 0; i < len(bundles); i++ {
		path, ok := bundles[i]
		if !ok {
			return nil, fmt.Errorf("log tree is missing entry bundle %d", i)
		}
		content, err := gitutil.CatFile(repoDir, LogRef+":"+path)
		if err != nil {
			return nil, fmt.Errorf("reading entry bundle %s: %w", path, err)
		}
		for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
			if line == "" {
				continue
			}
			e, err := ParseEntry(line)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}
	}
	return entries, nil
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

// EntriesFor returns every entry for a ref, in log order.
func (l *Log) EntriesFor(ref string) []Entry {
	var out []Entry
	for _, e := range l.entries {
		if e.Ref == ref {
			out = append(out, e)
		}
	}
	return out
}

// Latest returns the most recent entry for a ref.
func (l *Log) Latest(ref string) (Entry, bool) {
	for i := len(l.entries) - 1; i >= 0; i-- {
		if l.entries[i].Ref == ref {
			return l.entries[i], true
		}
	}
	return Entry{}, false
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

		var b strings.Builder
		for _, e := range l.entries[start:end] {
			b.WriteString(e.String())
			b.WriteByte('\n')
		}
		blob, err := gitutil.HashObject(l.repoDir, b.String())
		if err != nil {
			return fmt.Errorf("writing entry bundle: %w", err)
		}
		blobs[bundlePath(start/EntriesPerBundle, end-start)] = blob
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
