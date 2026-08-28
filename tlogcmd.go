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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	fpolicy "github.com/transparency-dev/formats/policy"
	whttp "github.com/transparency-dev/witness/client/http"
	"github.com/transparency-dev/witness/witness"

	"github.com/project-oak/git-ratchet/internal/gitlog"
	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// Checkpoint format modes. See docs/tlog-variant.md for how they differ.
const (
	// modeGitCheckpoint stores a signed note per ref, and witnesses enforce
	// Git ancestry when cosigning it.
	modeGitCheckpoint = "git-checkpoint"
	// modeTlog stores a Merkle transparency log in the repository, and
	// witnesses enforce only that the log grew by appending.
	modeTlog = "tlog"
)

// validateMode rejects anything that is not one of the two supported modes.
func validateMode(mode string) error {
	if mode != modeGitCheckpoint && mode != modeTlog {
		return fmt.Errorf("--mode must be %q or %q, got %q", modeGitCheckpoint, modeTlog, mode)
	}
	return nil
}

// logRefsTlog records each ref's current object in the repository's
// transparency log.
//
// This is the only command that grows the log, and it is local: no key, no
// network. The new entries sit past the stored checkpoint's size until
// checkpoint has a quorum cosign the log's new head, and until then they are
// evidence of nothing.
func logRefsTlog(repoDir string, refs []string) error {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return fmt.Errorf("opening log: %w", err)
	}
	before := l.Size()

	var added []string
	for _, ref := range refs {
		objectHash, err := gitutil.ResolveRef(repoDir, ref)
		if err != nil {
			return fmt.Errorf("resolving ref: %w", err)
		}
		records, err := l.RefRecords(ref)
		if err != nil {
			return err
		}
		// Skip a ref already at its latest logged state. This is what makes
		// log idempotent, and for tags that is load-bearing rather than
		// tidiness: a tag logged twice breaks the create-once rule and is
		// unverifiable from then on, even when both entries name the same
		// object.
		if len(records) > 0 && records[len(records)-1].Object == objectHash {
			continue
		}
		entry, err := gitlog.NewRefRecord(ref, objectHash)
		if err != nil {
			return err
		}
		l.Append(entry)
		added = append(added, ref+" "+objectHash)
	}

	if len(added) == 0 {
		fmt.Printf("nothing to log: every ref is already at its latest logged state (log size %d)\n", before)
		return nil
	}

	if err := checkLogChains(repoDir, l); err != nil {
		return fmt.Errorf("refusing to log: %w", err)
	}

	// The stored checkpoint is written back unchanged: it still describes the
	// tree a quorum cosigned, which is now a prefix of what the log holds.
	if err := l.Save(l.StoredCheckpoint(), "ratchet: log "+strings.Join(added, ", ")); err != nil {
		return err
	}

	stored, err := storedSize(l)
	if err != nil {
		return err
	}
	fmt.Printf("logged %d entries to %s (log size %d, %d not yet checkpointed)\n",
		len(added), gitlog.LogRef, l.Size(), l.Size()-stored)
	return nil
}

// checkpointRefFlag validates --ref for the commands that produce a
// checkpoint. A git-checkpoint covers one ref, so it needs the flag; a tlog
// checkpoint covers the whole log, whose contents are chosen by git-ratchet
// log, so a ref passed there asks for something the command will not do.
func checkpointRefFlag(mode, ref string) error {
	if mode == modeTlog {
		if ref != "" {
			return fmt.Errorf("--ref is not used with --mode %s: a checkpoint covers the whole log, "+
				"and a ref is recorded in it by `git-ratchet log --mode %s --ref %s`", modeTlog, modeTlog, ref)
		}
		return nil
	}
	if ref == "" {
		return fmt.Errorf("--ref is required with --mode %s", modeGitCheckpoint)
	}
	if _, err := gitutil.ParseRefKind(ref); err != nil {
		return fmt.Errorf("invalid --ref: %w", err)
	}
	return nil
}

// checkpointTlog has the log's current head cosigned by the policy's witnesses
// and stores the result. It covers whatever the log holds; entries get there
// through logRefsTlog.
func checkpointTlog(repoDir, origin string, signer *note.Signer, pol *fpolicy.TLogPolicy, client *http.Client, timeout time.Duration) error {
	l, oldSize, err := logToCheckpoint(repoDir)
	if err != nil {
		return err
	}

	cp := tlog.NewCheckpoint(origin, l.Size(), l.Root())
	signed, err := note.SignTlogCheckpoint(string(cp.Marshal()), signer)
	if err != nil {
		return fmt.Errorf("signing checkpoint: %w", err)
	}

	cosigLines, err := collectTlogCosignatures(pol, client, timeout, l, oldSize, signed)
	if err != nil {
		return err
	}

	assembled := signed
	for _, line := range cosigLines {
		assembled = note.AppendSignature(assembled, line)
	}
	// The origin signed the checkpoint itself, so all it needs to know is
	// that enough witnesses cosigned it.
	if !pol.Satisfied([]byte(assembled)) {
		return fmt.Errorf("quorum %q not satisfied by %d cosignatures", pol.Quorum, len(cosigLines))
	}

	if err := l.Save(assembled, checkpointMessage(l)); err != nil {
		return err
	}

	fmt.Printf("checkpoint stored at %s (log size %d, %d witness cosignatures)\n",
		gitlog.LogRef, l.Size(), len(cosigLines))
	return nil
}

// collectTlogCosignatures submits the signed checkpoint to every witness in
// the policy, in parallel, and returns the cosignature lines collected.
func collectTlogCosignatures(pol *fpolicy.TLogPolicy, client *http.Client, timeout time.Duration, l *gitlog.Log, oldSize uint64, signed string) ([]string, error) {
	type result struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses
	ch := make(chan result, len(witnesses))
	for _, w := range witnesses {
		go func(w fpolicy.Witness) {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if w.URL == nil {
				ch <- result{w.Name, "", fmt.Errorf("witness %s declares no URL", w.Name)}
				return
			}
			if w.URL.Scheme != "http" && w.URL.Scheme != "https" {
				ch <- result{w.Name, "", fmt.Errorf("unsupported witness transport %q for tlog mode", w.URL.Scheme)}
				return
			}
			line, err := cosignWithWitness(ctx, client, w.URL, l, oldSize, signed)
			ch <- result{w.Name, line, err}
		}(w)
	}

	var cosigLines []string
	for range witnesses {
		r := <-ch
		if r.err != nil {
			// A witness that inspected the transition and refused it is
			// evidence the log did not grow by appending, which is never
			// skipped in favour of another witness's quorum. A witness that
			// could not be reached, or that has fallen behind us, is not.
			if errors.Is(r.err, witness.ErrInvalidProof) || errors.Is(r.err, witness.ErrRootMismatch) {
				return nil, fmt.Errorf("witness %s rejected checkpoint: %w", r.policyName, r.err)
			}
			fmt.Fprintf(os.Stderr, "warning: witness %s failed (skipped): %v\n", r.policyName, r.err)
			continue
		}
		cosigLines = append(cosigLines, r.cosigLine)
	}
	return cosigLines, nil
}

// checkpointedLog opens the repository's log and returns the part of it that
// a checkpoint signed by the log and cosigned to the policy's quorum commits
// to. That prefix is everything verification is entitled to read.
func checkpointedLog(repoDir string, pol *fpolicy.TLogPolicy) (*gitlog.Log, error) {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}

	stored := l.StoredCheckpoint()
	if stored == "" {
		return nil, fmt.Errorf("no log checkpoint found (hint: git fetch origin %s:%s)", gitlog.LogRef, gitlog.LogRef)
	}

	// Verify covers both the log signature and the witness quorum, and only
	// accepts a checkpoint whose origin line matches the policy's log key.
	if _, err := pol.Verify([]byte(stored)); err != nil {
		return nil, fmt.Errorf("log checkpoint verification failed: %w", err)
	}

	body, err := note.ExtractBody(stored)
	if err != nil {
		return nil, fmt.Errorf("parsing log checkpoint: %w", err)
	}
	cp, _, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return nil, fmt.Errorf("malformed log checkpoint: %w", err)
	}
	return l.Checkpointed(cp)
}

// verifySingleRefTlog checks one ref against the verified log.
//
// Every ratchet property is established here, from entries held locally: a
// branch's logged states must each descend from the one before, and a tag must
// never move.
//
// Entries of unrecognised types are skipped, which can leave the latest logged
// state behind the real ref. The final comparison rejects a ref ahead of the
// log, so that case fails rather than passing quietly.
func verifySingleRefTlog(repoDir, ref string, l *gitlog.Log) error {
	kind, err := gitutil.ParseRefKind(ref)
	if err != nil {
		return err
	}

	entries, err := l.RefRecords(ref)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no log entries for ref %q", ref)
	}

	if err := checkRefChain(repoDir, ref, kind, entries); err != nil {
		return err
	}

	latest := entries[len(entries)-1]
	localHash, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return fmt.Errorf("resolving ref: %w", err)
	}

	if kind == gitutil.RefTag {
		if localHash != latest.Object {
			return fmt.Errorf("tag does not match log (current: %s, logged: %s)", localHash, latest.Object)
		}
		return nil
	}

	ok, err := gitutil.IsAncestor(repoDir, localHash, latest.Object)
	if err != nil {
		return fmt.Errorf("checking ancestry: %w", err)
	}
	if !ok {
		return fmt.Errorf("local commit %s is ahead of the latest logged commit %s", localHash, latest.Object)
	}
	return nil
}

// cosignWithWitness performs one add-checkpoint exchange with a witness.
//
// A witness holding a different size answers with the size it does hold, and
// the proof has to be regenerated from there: a consistency proof is anchored
// to a specific size, unlike the commit chain git-checkpoint mode sends, which
// spans any gap. One retry is enough, because the size the witness reports is
// the size it will accept.
func cosignWithWitness(ctx context.Context, client *http.Client, endpoint *url.URL, l *gitlog.Log, oldSize uint64, signed string) (string, error) {
	w := whttp.NewWitness(endpoint, client)

	submit := func(from uint64) ([]byte, uint64, error) {
		proof, err := l.ConsistencyProofFrom(from)
		if err != nil {
			return nil, 0, fmt.Errorf("generating consistency proof from size %d: %w", from, err)
		}
		return w.Update(ctx, from, []byte(signed), rawHashes(proof))
	}

	cosig, actualSize, err := submit(oldSize)
	if errors.Is(err, witness.ErrCheckpointStale) && actualSize != oldSize {
		cosig, _, err = submit(actualSize)
		if err != nil {
			return "", fmt.Errorf("retry from witness size %d: %w", actualSize, err)
		}
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(cosig)), nil
}

// rawHashes converts proof hashes to the byte slices the witness client takes.
func rawHashes(hs []tlog.Hash) [][]byte {
	out := make([][]byte, 0, len(hs))
	for _, h := range hs {
		out = append(out, h[:])
	}
	return out
}

// dropRepeats collapses runs of entries naming the same object.
//
// Logging a ref that has not moved states nothing new, so a repeated entry is
// not a second statement about the ref and must not be read as one. For a tag
// that is the difference between a repeat and a move.
func dropRepeats(entries []gitlog.RefRecord) []gitlog.RefRecord {
	out := make([]gitlog.RefRecord, 0, len(entries))
	for i, e := range entries {
		if i > 0 && entries[i-1].Object == e.Object {
			continue
		}
		out = append(out, e)
	}
	return out
}

// checkRefChain applies the ratchet rule to a ref's logged entries: a branch's
// entries must each descend from the one before, and a tag must never move. It
// says nothing about the repository's current ref.
func checkRefChain(repoDir, ref string, kind gitutil.RefKind, entries []gitlog.RefRecord) error {
	entries = dropRepeats(entries)
	switch kind {
	case gitutil.RefTag:
		// Tags are create-once. Repeats have been collapsed, so anything left
		// beyond the first entry is the tag naming a second object.
		if len(entries) > 1 {
			return fmt.Errorf("tag %s moved: logged at %s and later at %s; a tag must be logged at one object only",
				ref, entries[0].Object, entries[1].Object)
		}
	case gitutil.RefBranch:
		for i := 1; i < len(entries); i++ {
			prev, curr := entries[i-1].Object, entries[i].Object
			ok, err := gitutil.IsAncestor(repoDir, prev, curr)
			if err != nil {
				return fmt.Errorf("cannot check ancestry from logged commit %s to %s "+
					"(the object may be missing from this clone, which is itself evidence "+
					"that logged history was discarded): %w", prev, curr, err)
			}
			if !ok {
				return fmt.Errorf("log entry %d for %s (%s) does not descend from entry %d (%s): history was rewritten",
					i, ref, curr, i-1, prev)
			}
		}
	}
	return nil
}

// checkLogChains applies the ratchet rule to every ref the log names.
//
// A cosigned entry is permanent: every entry in a tree a quorum signed is in
// the prefix of every later checkpoint, verification walks a ref's entries
// from the start, and there is no statement that withdraws one. An entry that
// breaks its ref's chain therefore makes that ref unverifiable for good, and
// the usual way to produce one is not an attack but a force-push followed by
// an ordinary `git-ratchet log` run.
//
// Callers run this at the two points where the entries can still be dropped:
// before writing them, and before asking a quorum to cosign them.
func checkLogChains(repoDir string, l *gitlog.Log) error {
	refs, err := l.Refs()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		kind, err := gitutil.ParseRefKind(ref)
		if err != nil {
			return fmt.Errorf("log names an unrecognised ref %q: %w", ref, err)
		}
		entries, err := l.RefRecords(ref)
		if err != nil {
			return err
		}
		if err := checkRefChain(repoDir, ref, kind, entries); err != nil {
			return err
		}
	}
	return nil
}

// checkpointRequestTlog builds the add-checkpoint request a witness needs,
// without contacting one and without writing to the log.
//
// It describes the log as it stands. Nothing durable changes here, so a log
// entry landing before checkpointStoreTlog runs invalidates the request rather
// than corrupting anything; that command says so and the request is rebuilt.
func checkpointRequestTlog(repoDir, origin string, signer *note.Signer) (request, signedNote string, err error) {
	l, oldSize, err := logToCheckpoint(repoDir)
	if err != nil {
		return "", "", err
	}

	cp := tlog.NewCheckpoint(origin, l.Size(), l.Root())
	signedNote, err = note.SignTlogCheckpoint(string(cp.Marshal()), signer)
	if err != nil {
		return "", "", fmt.Errorf("signing checkpoint: %w", err)
	}

	proof, err := l.ConsistencyProofFrom(oldSize)
	if err != nil {
		return "", "", fmt.Errorf("generating consistency proof from size %d: %w", oldSize, err)
	}
	return iwitness.FormatTlogRequest(oldSize, proof, signedNote), signedNote, nil
}

// checkpointStoreTlog stores a checkpoint assembled elsewhere, after checking
// that the cosignatures cover the tree the log currently holds.
func checkpointStoreTlog(repoDir, assembled string, pol *fpolicy.TLogPolicy) error {
	if _, err := pol.Verify([]byte(assembled)); err != nil {
		return fmt.Errorf("checkpoint rejected by policy: %w", err)
	}

	body, err := note.ExtractBody(assembled)
	if err != nil {
		return fmt.Errorf("parsing checkpoint: %w", err)
	}
	cp, cpRoot, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return fmt.Errorf("malformed checkpoint: %w", err)
	}

	l, err := gitlog.Open(repoDir)
	if err != nil {
		return fmt.Errorf("opening log: %w", err)
	}
	// The cosignatures are over a tree, so the only way to know they apply to
	// what is about to be written is to rebuild that tree and compare. The
	// chains are not rechecked here: that check exists to keep a broken one
	// from being cosigned, and by now it has been.
	if cp.Size != l.Size() || l.Root() != cpRoot {
		return fmt.Errorf("checkpoint commits to a tree of size %d that this repository does not reproduce "+
			"(the log holds %d entries); the log may have grown since checkpoint-request, in which case "+
			"rebuild the request", cp.Size, l.Size())
	}

	if err := l.Save(assembled, checkpointMessage(l)); err != nil {
		return err
	}
	fmt.Printf("checkpoint stored at %s (log size %d)\n", gitlog.LogRef, l.Size())
	return nil
}

// logToCheckpoint opens the log and returns it with the tree size the
// witnesses are expected to be holding, which is the size of the checkpoint
// this repository stored last. A witness that disagrees says so, and the
// client regenerates its proof from the size the witness actually holds.
func logToCheckpoint(repoDir string) (*gitlog.Log, uint64, error) {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return nil, 0, fmt.Errorf("opening log: %w", err)
	}
	if l.Size() == 0 {
		return nil, 0, fmt.Errorf("refusing to checkpoint an empty log (hint: git-ratchet log --mode %s --ref <ref>)", modeTlog)
	}
	// Entries reach the log ref by being pushed to it, not only through
	// git-ratchet log, so the chains are checked again before a quorum is
	// asked to cosign them. An entry that has been cosigned cannot be
	// withdrawn; one that has not can still be dropped by resetting the log
	// ref to its last checkpointed commit.
	if err := checkLogChains(repoDir, l); err != nil {
		return nil, 0, fmt.Errorf("refusing to checkpoint: %w", err)
	}
	oldSize, err := storedSize(l)
	if err != nil {
		return nil, 0, err
	}
	return l, oldSize, nil
}

// storedSize returns the size of the checkpoint the log ref carries, or zero
// if the log has never been checkpointed.
func storedSize(l *gitlog.Log) (uint64, error) {
	stored := l.StoredCheckpoint()
	if stored == "" {
		return 0, nil
	}
	body, err := note.ExtractBody(stored)
	if err != nil {
		return 0, fmt.Errorf("parsing stored checkpoint: %w", err)
	}
	cp, _, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return 0, fmt.Errorf("parsing stored checkpoint: %w", err)
	}
	return cp.Size, nil
}

// checkpointMessage describes a log commit, for anyone reading git log on the
// log ref.
func checkpointMessage(l *gitlog.Log) string {
	return fmt.Sprintf("ratchet: checkpoint at log size %d", l.Size())
}
