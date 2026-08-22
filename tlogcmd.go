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
	"os"
	"strings"
	"time"

	"github.com/project-oak/git-ratchet/internal/gitlog"
	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/policy"
	"github.com/project-oak/git-ratchet/internal/tlog"
	"github.com/project-oak/git-ratchet/internal/witness"
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

// checkpointTlog appends the ref's current object hash to the repository's
// transparency log, has the log's new head cosigned by the policy's witnesses,
// and commits both to the log ref.
func checkpointTlog(repoDir, ref, origin string, signer *note.Signer, pol *policy.Policy) error {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return fmt.Errorf("opening log: %w", err)
	}

	objectHash, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return fmt.Errorf("resolving ref: %w", err)
	}

	// The size the witnesses are expected to be holding is the size of the
	// last checkpoint this repository stored. If a witness disagrees it says
	// so, and the client regenerates its proof from the size the witness
	// actually holds.
	oldSize := 0
	if stored := l.StoredCheckpoint(); stored != "" {
		body, err := note.ExtractBody(stored)
		if err != nil {
			return fmt.Errorf("parsing stored checkpoint: %w", err)
		}
		prev, err := tlog.ParseCheckpoint(body)
		if err != nil {
			return fmt.Errorf("parsing stored checkpoint: %w", err)
		}
		oldSize = prev.Size
	}

	// Appending an entry identical to the ref's latest logged state would grow
	// the log without saying anything new, so re-checkpointing an unchanged
	// ref just refreshes the cosignatures on the current head.
	updates, err := l.RefUpdates(ref)
	if err != nil {
		return err
	}
	appended := false
	if len(updates) == 0 || updates[len(updates)-1].Object != objectHash {
		entry, err := gitlog.NewRefUpdate(ref, objectHash)
		if err != nil {
			return err
		}
		l.Append(entry)
		appended = true
	}
	if l.Size() == 0 {
		return fmt.Errorf("refusing to checkpoint an empty log")
	}

	cp := tlog.Checkpoint{Origin: origin, Size: l.Size(), Root: l.Root()}
	signed, err := note.Sign(cp.Body(), signer)
	if err != nil {
		return fmt.Errorf("signing checkpoint: %w", err)
	}

	cosigLines, err := collectTlogCosignatures(pol, l, oldSize, signed)
	if err != nil {
		return err
	}

	assembled := signed
	for _, line := range cosigLines {
		assembled = note.AppendSignature(assembled, line)
	}
	body, sigLines, err := note.ParseSignedNote(assembled)
	if err != nil {
		return fmt.Errorf("parsing assembled checkpoint: %w", err)
	}
	if err := pol.VerifyQuorumTlog(body, sigLines); err != nil {
		return fmt.Errorf("quorum not satisfied: %w", err)
	}

	msg := fmt.Sprintf("ratchet: %s %s (log size %d)", ref, objectHash, l.Size())
	if !appended {
		msg = fmt.Sprintf("ratchet: refresh cosignatures at log size %d", l.Size())
	}
	if err := l.Save(assembled, msg); err != nil {
		return err
	}

	fmt.Printf("checkpoint stored at %s (log size %d, %d witness cosignatures)\n",
		gitlog.LogRef, l.Size(), len(cosigLines))
	return nil
}

// collectTlogCosignatures submits the signed checkpoint to every witness in
// the policy, in parallel, and returns the cosignature lines collected.
func collectTlogCosignatures(pol *policy.Policy, l *gitlog.Log, oldSize int, signed string) ([]string, error) {
	proofFor := func(m int) ([]tlog.Hash, error) { return l.ConsistencyProofFrom(m) }

	type result struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses()
	ch := make(chan result, len(witnesses))
	for _, w := range witnesses {
		go func(w *policy.Witness) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if w.Endpoint != "" && !strings.HasPrefix(w.Endpoint, "http://") && !strings.HasPrefix(w.Endpoint, "https://") {
				ch <- result{w.PolicyName, "", fmt.Errorf("unsupported witness transport %q for tlog mode", w.Endpoint)}
				return
			}
			line, err := witness.CosignTlog(ctx, w.Endpoint, oldSize, proofFor, signed)
			ch <- result{w.PolicyName, line, err}
		}(w)
	}

	var cosigLines []string
	for range witnesses {
		r := <-ch
		if r.err != nil {
			// A rejection means the witness inspected the transition and
			// refused it — the log did not grow by appending. That is the
			// strongest signal available that the log has been rewritten, so
			// it is never skipped in favour of another witness's quorum.
			var rejection *witness.RejectionError
			if errors.As(r.err, &rejection) {
				return nil, fmt.Errorf("witness %s rejected checkpoint: %w", r.policyName, r.err)
			}
			fmt.Fprintf(os.Stderr, "warning: witness %s failed (skipped): %v\n", r.policyName, r.err)
			continue
		}
		cosigLines = append(cosigLines, r.cosigLine)
	}
	return cosigLines, nil
}

// openVerifiedLog opens the repository's log and checks that its stored
// checkpoint is signed, has quorum, and describes the log actually present.
func openVerifiedLog(repoDir string, pol *policy.Policy) (*gitlog.Log, error) {
	l, err := gitlog.Open(repoDir)
	if err != nil {
		return nil, fmt.Errorf("opening log: %w", err)
	}

	stored := l.StoredCheckpoint()
	if stored == "" {
		return nil, fmt.Errorf("no log checkpoint found (hint: git fetch origin %s:%s)", gitlog.LogRef, gitlog.LogRef)
	}

	body, sigLines, err := note.ParseSignedNote(stored)
	if err != nil {
		return nil, fmt.Errorf("parsing log checkpoint: %w", err)
	}
	if err := pol.VerifyTlog(body, sigLines); err != nil {
		return nil, fmt.Errorf("log checkpoint verification failed: %w", err)
	}

	cp, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return nil, fmt.Errorf("malformed log checkpoint: %w", err)
	}
	if cp.Origin != pol.LogName {
		return nil, fmt.Errorf("checkpoint origin mismatch: checkpoint is from %q but policy expects %q", cp.Origin, pol.LogName)
	}

	// The entries present must be exactly the tree the witnesses cosigned.
	// Anything else means entries were added or removed without witnessing.
	if cp.Size != l.Size() {
		return nil, fmt.Errorf("log has %d entries but the cosigned checkpoint commits to %d", l.Size(), cp.Size)
	}
	if l.Root() != cp.Root {
		return nil, fmt.Errorf("log entries do not reproduce the cosigned root hash")
	}

	// Refuse a log containing statements this implementation cannot interpret,
	// rather than verifying the part of it that happens to be legible.
	if err := l.CheckEntryTypes(); err != nil {
		return nil, err
	}
	return l, nil
}

// verifySingleRefTlog checks one ref against the verified log.
//
// This is the walk that replaces the witness's ancestry check: the witness
// only attested that the log grew by appending, so every ratchet property is
// established here, from entries the verifier holds locally.
func verifySingleRefTlog(repoDir, ref string, l *gitlog.Log) error {
	kind, err := gitutil.ParseRefKind(ref)
	if err != nil {
		return err
	}

	entries, err := l.RefUpdates(ref)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("no log entries for ref %q", ref)
	}

	switch kind {
	case gitutil.RefTag:
		// Tags are create-once: a second entry for the same tag is a move,
		// whatever object it names.
		if len(entries) > 1 {
			return fmt.Errorf("tag was logged %d times (first %s, last %s); tags must be logged exactly once",
				len(entries), entries[0].Object, entries[len(entries)-1].Object)
		}
	case gitutil.RefBranch:
		// Each logged state must descend from the one before it.
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
