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

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/persistence/inmemory"
	"github.com/transparency-dev/witness/witness"
	"golang.org/x/mod/sumdb/note"

	inote "github.com/project-oak/git-ratchet/internal/note"
)

// fixture is a repository wired up to a running witness.
type fixture struct {
	ratchetBin string
	repoDir    string
	keyPath    string
	policyPath string

	witnessKey *inote.Signer
	originKey  *inote.Signer
	witnessURL string
	cosignBin  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithKeys(t, inote.Ed25519Origin, inote.Ed25519Cosigner)
}

// newFixtureWithKeys builds the fixture with keys of the given algorithms.
// An ML-DSA-44 key is accepted in either role, so the combination a
// post-quantum deployment runs is exercised alongside the Ed25519 one.
func newFixtureWithKeys(t *testing.T, originType, witnessType inote.SigType) *fixture {
	t.Helper()

	f := &fixture{
		ratchetBin: mustFindBinary(t),
		originKey:  mustGenerateKey(t, "test-origin", originType, inote.RoleOrigin),
		witnessKey: mustGenerateKey(t, "test-witness", witnessType, inote.RoleCosigner),
	}
	f.repoDir = initTestRepo(t)

	tmpDir := t.TempDir()
	f.keyPath = writeKeyFile(t, tmpDir, f.originKey)

	f.cosignBin = mustFindCosignBinary(t)
	f.witnessURL = startWitness(t, f.originKey, f.witnessKey)
	f.policyPath = writePolicyFile(t, f.repoDir, f.originKey, f.witnessKey, f.witnessURL)
	return f
}

// writePolicyFile writes a policy in the field order tlog-policy defines:
// the vkey precedes the optional URL.
func writePolicyFile(t *testing.T, dir string, log, witness *inote.Signer, witnessURL string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.txt")
	body := fmt.Sprintf("log %s\nwitness w1 %s %s\n\nquorum w1\n", log.VKey(), witness.VKey(), witnessURL)
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// startWitness runs transparency-dev/witness in this process and returns
// its base URL. git-ratchet ships no witness for this mode, so the client is
// tested against the implementation it will meet in production.
func startWitness(t *testing.T, originKey, witnessKey *inote.Signer) string {
	t.Helper()

	signer, err := fnote.NewSignerForCosignatureV1(mustSkey(t, witnessKey))
	if err != nil {
		t.Fatalf("witness signer: %v", err)
	}
	originVerifier, err := fnote.NewVerifier(originKey.VKey())
	if err != nil {
		t.Fatalf("origin verifier: %v", err)
	}

	w, err := witness.New(t.Context(), witness.Opts{
		Persistence: inmemory.New(),
		Signers:     []note.Signer{signer},
		VerifierForLog: func(_ context.Context, origin string) (note.Verifier, bool, error) {
			if origin != originVerifier.Name() {
				return nil, false, nil
			}
			return originVerifier, true, nil
		},
	})
	if err != nil {
		t.Fatalf("witness.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/add-checkpoint", witness.NewAddCheckpointHandler(w.Update))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// logRefs runs git-ratchet log, returning its output.
func (f *fixture) logRefs(t *testing.T, refs ...string) (string, error) {
	t.Helper()
	args := []string{"log", "--repo", f.repoDir}
	for _, ref := range refs {
		args = append(args, "--ref", ref)
	}
	out, err := exec.Command(f.ratchetBin, args...).CombinedOutput()
	return string(out), err
}

func (f *fixture) mustLogRefs(t *testing.T, refs ...string) string {
	t.Helper()
	out, err := f.logRefs(t, refs...)
	if err != nil {
		t.Fatalf("log %v failed: %v\n%s", refs, err, out)
	}
	return out
}

// checkpoint runs git-ratchet checkpoint, returning its output.
// It takes no ref: a checkpoint covers whatever the log holds.
func (f *fixture) checkpoint(t *testing.T) (string, error) {
	t.Helper()
	out, err := exec.Command(f.ratchetBin,
		"checkpoint",

		"--repo", f.repoDir,
		"--key", f.keyPath,
		"--policy", f.policyPath,
	).CombinedOutput()
	return string(out), err
}

// checkpointWithAPI runs checkpoint with the GitHub API pointed at a stub, as
// GITHUB_API_URL does on an Enterprise instance.
func (f *fixture) checkpointWithAPI(t *testing.T, api string) (string, error) {
	t.Helper()
	cmd := exec.Command(f.ratchetBin,
		"checkpoint",

		"--repo", f.repoDir,
		"--key", f.keyPath,
		"--policy", f.policyPath,
		"--github-token", "test-token",
		"--witness-timeout", "30s",
	)
	cmd.Env = append(os.Environ(), "GITHUB_API_URL="+api)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (f *fixture) mustCheckpoint(t *testing.T) string {
	t.Helper()
	out, err := f.checkpoint(t)
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}
	return out
}

// logAndCheckpoint records the refs and then checkpoints the log: the pair of
// commands a routine ratchet run makes.
func (f *fixture) logAndCheckpoint(t *testing.T, refs ...string) string {
	t.Helper()
	f.mustLogRefs(t, refs...)
	return f.mustCheckpoint(t)
}

// verify runs git-ratchet verify, returning its output.
func (f *fixture) verify(t *testing.T, refs ...string) (string, error) {
	t.Helper()
	args := []string{"verify", "--repo", f.repoDir, "--policy", f.policyPath}
	for _, ref := range refs {
		args = append(args, "--ref", ref)
	}
	out, err := exec.Command(f.ratchetBin, args...).CombinedOutput()
	return string(out), err
}

// TestReplaceRefIgnored covers a bypass that replace refs would otherwise
// open. A replace ref substitutes one object's content for another's wherever
// git reads it, so forging a stand-in for a logged commit whose parent is an
// unlogged commit puts that commit into the logged one's ancestry -- and the
// ancestry check accepts a ref the log never covered. Reads pass
// --no-replace-objects, so the substitution has no effect here.
func TestReplaceRefIgnored(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "logged commit")
	f.logAndCheckpoint(t, "refs/heads/main")
	logged := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", "HEAD"))

	// A commit on the branch that was never submitted to the log.
	makeCommit(t, f.repoDir, "unlogged commit")
	unlogged := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", "HEAD"))

	if out, err := f.verify(t, "refs/heads/main"); err == nil {
		t.Fatalf("verify accepted an unlogged commit before any replace ref:\n%s", out)
	}

	// Substitute a stand-in for the logged commit that descends from the
	// unlogged one. Ordinary git reads of the logged hash now walk through it.
	tree := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", logged+"^{tree}"))
	forged := strings.TrimSpace(runOutput(t, f.repoDir,
		"git", "commit-tree", tree, "-p", unlogged, "-m", "forged stand-in"))
	run(t, f.repoDir, "git", "replace", "-f", logged, forged)

	out, err := f.verify(t, "refs/heads/main")
	if err == nil {
		t.Fatalf("verify accepted an unlogged commit through a replace ref:\n%s", out)
	}
	if !strings.Contains(out, unlogged) {
		t.Errorf("expected the failure to name the unlogged commit %s:\n%s", unlogged, out)
	}
}

// TestIntegration walks the happy path: successive fast-forward commits are
// logged, cosigned, and verify cleanly.
func TestIntegration(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after first checkpoint: %v\n%s", err, out)
	}

	// A commit that has not been logged leaves the branch ahead of the log.
	makeCommit(t, f.repoDir, "second commit")
	if out, err := f.verify(t, "refs/heads/main"); err == nil {
		t.Errorf("verify should fail while HEAD is ahead of the log:\n%s", out)
	}

	// Logging it is not enough either: until a quorum has cosigned a
	// checkpoint covering the entry, nothing verifies against it.
	f.mustLogRefs(t, "refs/heads/main")
	if out, err := f.verify(t, "refs/heads/main"); err == nil {
		t.Errorf("verify should fail while the new entry is uncosigned:\n%s", out)
	}

	f.mustCheckpoint(t)
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after second checkpoint: %v\n%s", err, out)
	}

	makeCommit(t, f.repoDir, "third commit")
	out := f.logAndCheckpoint(t, "refs/heads/main")
	if !strings.Contains(out, "log size 3") {
		t.Errorf("expected the log to have grown to 3 entries, got: %s", out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after third checkpoint: %v\n%s", err, out)
	}

	// The log lives in the repository as a commit ref.
	if out := runOutput(t, f.repoDir, "git", "cat-file", "-t", "refs/ratchet/log"); strings.TrimSpace(out) != "commit" {
		t.Errorf("refs/ratchet/log should be a commit, got %q", strings.TrimSpace(out))
	}
}

// TestLoggingUnchangedRefDoesNotGrowLog checks that a ref which has not
// moved adds nothing, and that checkpointing again refreshes the cosignatures
// on the log's existing head.
func TestLoggingUnchangedRefDoesNotGrowLog(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "only commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	out := f.mustLogRefs(t, "refs/heads/main")
	if !strings.Contains(out, "nothing to log") {
		t.Errorf("logging an unchanged ref should add no entry, got: %s", out)
	}

	out = f.mustCheckpoint(t)
	if !strings.Contains(out, "log size 1") {
		t.Errorf("re-checkpointing should leave the log at size 1, got: %s", out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after refresh: %v\n%s", err, out)
	}
}

// TestLogRefusesRollback is the central test for this mode.
//
// A witness cannot help here: it attests only that the log grew by appending,
// and a consistency proof says nothing about Git ancestry, so it would cosign a
// rollback quite happily. Nor can verify undo one, because a cosigned entry is
// in the prefix of every later checkpoint for good. The rollback therefore has
// to be refused before the entry is written, which also leaves the log ref
// untouched so the branch can be put back.
func TestLogRefusesRollback(t *testing.T) {
	f := newFixture(t)

	first := makeCommit(t, f.repoDir, "first commit")
	makeCommit(t, f.repoDir, "second commit")
	f.logAndCheckpoint(t, "refs/heads/main")
	logHead := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", "refs/ratchet/log"))

	run(t, f.repoDir, "git", "reset", "--hard", first)

	out, err := f.logRefs(t, "refs/heads/main")
	if err == nil {
		t.Fatalf("log should refuse to record a rollback:\n%s", out)
	}
	if !strings.Contains(out, "refusing to log") || !strings.Contains(out, "history was rewritten") {
		t.Errorf("expected a refusal naming the rewrite, got:\n%s", out)
	}

	if now := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", "refs/ratchet/log")); now != logHead {
		t.Errorf("log ref moved despite the refusal: %s -> %s", logHead, now)
	}
}

// TestCheckpointRefusesUnverifiableChain covers the second place the chain
// is checked. The log ref is written by git-ratchet log, but it is a Git ref
// like any other and can be pushed to directly, so the chains are checked again
// before a quorum is asked to cosign them. Here the break is not a bad entry
// but a missing object: the branch was rolled back and collected after its tip
// had been logged, so the ancestry the log asserts can no longer be shown.
func TestCheckpointRefusesUnverifiableChain(t *testing.T) {
	f := newFixture(t)

	first := makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	makeCommit(t, f.repoDir, "second commit")
	f.mustLogRefs(t, "refs/heads/main")

	// The second commit is logged but not yet cosigned. Drop it from the
	// repository, as a rollback followed by garbage collection would.
	run(t, f.repoDir, "git", "reset", "--hard", first)
	run(t, f.repoDir, "git", "reflog", "expire", "--expire=now", "--all")
	run(t, f.repoDir, "git", "gc", "--prune=now")

	out, err := f.checkpoint(t)
	if err == nil {
		t.Fatalf("checkpoint should refuse a chain it cannot check:\n%s", out)
	}
	if !strings.Contains(out, "refusing to checkpoint") || !strings.Contains(out, "missing from this clone") {
		t.Errorf("expected a refusal naming the missing object, got:\n%s", out)
	}
}

// TestLogRefusesTagMove checks the create-once rule for tags: a tag logged
// twice is a moved tag, whatever it points at, and logging it a second time
// cannot be taken back.
func TestLogRefusesTagMove(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	run(t, f.repoDir, "git", "tag", "v1.0.0")
	f.logAndCheckpoint(t, "refs/tags/v1.0.0")
	if out, err := f.verify(t, "refs/tags/v1.0.0"); err != nil {
		t.Fatalf("verify after tagging: %v\n%s", err, out)
	}

	// Move the tag and log it again.
	makeCommit(t, f.repoDir, "second commit")
	run(t, f.repoDir, "git", "tag", "-f", "v1.0.0")

	out, err := f.logRefs(t, "refs/tags/v1.0.0")
	if err == nil {
		t.Fatalf("log should refuse to record a tag twice:\n%s", out)
	}
	if !strings.Contains(out, "a tag must be logged at one object only") {
		t.Errorf("expected a create-once diagnostic, got:\n%s", out)
	}

	// The first entry still stands, so the tag at its logged object verifies.
	run(t, f.repoDir, "git", "tag", "-f", "v1.0.0", "HEAD~1")
	if out, err := f.verify(t, "refs/tags/v1.0.0"); err != nil {
		t.Fatalf("verify should still pass for the tag as first logged: %v\n%s", err, out)
	}
}

// TestVerifyRejectsUnloggedRef checks that a ref with no entries is not
// silently treated as verified.
func TestVerifyRejectsUnloggedRef(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	run(t, f.repoDir, "git", "branch", "other")
	out, err := f.verify(t, "refs/heads/other")
	if err == nil {
		t.Fatalf("verify should reject a ref with no log entries:\n%s", out)
	}
	if !strings.Contains(out, "no log entries") {
		t.Errorf("expected a no-entries diagnostic, got:\n%s", out)
	}
}

// TestVerifyRejectsTamperedCheckpoint checks that the stored checkpoint's
// signature is actually enforced.
func TestVerifyRejectsTamperedCheckpoint(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	// Rewrite the checkpoint blob inside the log tree, keeping the tree
	// otherwise intact, and repoint the log ref at the result.
	original := runOutput(t, f.repoDir, "git", "cat-file", "-p", "refs/ratchet/log:checkpoint")
	tampered := []byte(original)
	for i := len(tampered) - 5; i < len(tampered)-1; i++ {
		tampered[i] ^= 0xFF
	}
	blob := gitStdin(t, f.repoDir, string(tampered), "hash-object", "-w", "--stdin")

	indexFile := filepath.Join(t.TempDir(), "index")
	gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile}, "read-tree", "refs/ratchet/log^{tree}")
	gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile},
		"update-index", "--add", "--cacheinfo", "100644,"+blob+",checkpoint")
	tree := strings.TrimSpace(gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile}, "write-tree"))
	commit := strings.TrimSpace(gitEnv(t, f.repoDir, []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	}, "commit-tree", tree, "-m", "tampered"))
	run(t, f.repoDir, "git", "update-ref", "refs/ratchet/log", commit)

	out, err := f.verify(t, "refs/heads/main")
	if err == nil {
		t.Fatalf("verify should reject a tampered checkpoint:\n%s", out)
	}
}

// TestWitnessSizeConflictRecovery checks the 409 recovery path: a witness
// that has lost its state reports the size it actually holds, and the client
// regenerates its proof and resubmits without operator intervention.
func TestWitnessSizeConflictRecovery(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")
	makeCommit(t, f.repoDir, "second commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	// Replace the witness with a fresh one holding no state, keeping its key.
	// The client still believes the witness holds a tree of size 2.
	f.witnessURL = startWitness(t, f.originKey, f.witnessKey)
	f.policyPath = writePolicyFile(t, f.repoDir, f.originKey, f.witnessKey, f.witnessURL)

	makeCommit(t, f.repoDir, "third commit")
	f.mustLogRefs(t, "refs/heads/main")
	if out, err := f.checkpoint(t); err != nil {
		t.Fatalf("checkpoint should recover from a witness size conflict: %v\n%s", err, out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after conflict recovery: %v\n%s", err, out)
	}
}

// TestMultipleRefsShareOneLog checks that branches and tags coexist in a
// single log and are each verified against their own entries.
func TestMultipleRefsShareOneLog(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	run(t, f.repoDir, "git", "tag", "v1.0.0")
	// Both refs go in as one batch, under one checkpoint.
	f.logAndCheckpoint(t, "refs/heads/main", "refs/tags/v1.0.0")

	makeCommit(t, f.repoDir, "second commit")
	out := f.logAndCheckpoint(t, "refs/heads/main")
	if !strings.Contains(out, "log size 3") {
		t.Errorf("expected three entries across both refs, got: %s", out)
	}

	if out, err := f.verify(t, "refs/heads/main", "refs/tags/v1.0.0"); err != nil {
		t.Fatalf("verify of both refs: %v\n%s", err, out)
	}
}

// gitStdin runs a git command with content on stdin and returns trimmed output.
func gitStdin(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s failed: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// gitEnv runs a git command with extra environment variables.
func gitEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// mustSkey returns a key in the C2SP signed-note private key encoding, which
// is what the reference witness signs with.
func mustSkey(t *testing.T, s *inote.Signer) string {
	t.Helper()
	skey, err := s.SKey()
	if err != nil {
		t.Fatalf("rendering private key: %v", err)
	}
	return skey
}

// TestUnwitnessedEntriesAreIgnored covers the trust boundary end to end.
//
// The log ref is rewritten to carry the entries from a second checkpoint while
// keeping the first checkpoint, which is what an attacker with push access to
// the log ref can produce: they can append entries, but they cannot make a
// witness attest to them. Verification reads the witnessed prefix only, so a
// ref inside that prefix still verifies, and a ref beyond it does not.
func TestUnwitnessedEntriesAreIgnored(t *testing.T) {
	f := newFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.logAndCheckpoint(t, "refs/heads/main")
	firstCommit := strings.TrimSpace(runOutput(t, f.repoDir, "git", "rev-parse", "refs/heads/main"))
	firstCheckpoint := runOutput(t, f.repoDir, "git", "cat-file", "-p", "refs/ratchet/log:checkpoint")

	makeCommit(t, f.repoDir, "second commit")
	f.logAndCheckpoint(t, "refs/heads/main")

	// Two entries in the tree, but the checkpoint of the first, which commits
	// to one. The second entry is present and unwitnessed.
	blob := gitStdin(t, f.repoDir, firstCheckpoint, "hash-object", "-w", "--stdin")
	indexFile := filepath.Join(t.TempDir(), "index")
	gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile}, "read-tree", "refs/ratchet/log^{tree}")
	gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile},
		"update-index", "--add", "--cacheinfo", "100644,"+blob+",checkpoint")
	tree := strings.TrimSpace(gitEnv(t, f.repoDir, []string{"GIT_INDEX_FILE=" + indexFile}, "write-tree"))
	commit := strings.TrimSpace(gitEnv(t, f.repoDir, []string{
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
	}, "commit-tree", tree, "-m", "unwitnessed entry"))
	run(t, f.repoDir, "git", "update-ref", "refs/ratchet/log", commit)

	// main is at the second commit, which only the unwitnessed entry names.
	if out, err := f.verify(t, "refs/heads/main"); err == nil {
		t.Fatalf("verify should not trust a ref named only by an unwitnessed entry:\n%s", out)
	}

	// Moved back inside the witnessed prefix, the same log verifies: the extra
	// entry is not evidence of anything, so it is neither trusted nor fatal.
	run(t, f.repoDir, "git", "update-ref", "refs/heads/main", firstCommit)
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify should accept a ref inside the witnessed prefix: %v\n%s", err, out)
	}
}

// mustFindCosignBinary locates the compiled cosign binary from Bazel runfiles.
func mustFindCosignBinary(t *testing.T) string {
	t.Helper()
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			for _, p := range []string{
				filepath.Join(srcDir, ws, "cosign", "cosign_", "cosign"),
				filepath.Join(srcDir, ws, "cosign", "cosign"),
			} {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Skip("cosign binary not found; run with: bazel test //e2e:e2e_test")
	return ""
}

// startIssueWitness runs a witness reachable as github-issue://owner/repo.
//
// It stands up enough of the GitHub REST API for the transport to work
// against -- create an issue, read it, read its comments -- and behind that
// runs the real cosign binary on the issue body, as the witness repository's
// workflow does. Every part is the shipped one: the transport speaks HTTP to
// the API stub, cosign parses the message and answers with the standard
// add-checkpoint handler, and its state ratchets in a file between rounds.
//
// It returns the API root to point the transport at.
func startIssueWitness(t *testing.T, originKey, witnessKey *inote.Signer) string {
	t.Helper()
	dir := t.TempDir()
	witnessKeyPath := filepath.Join(dir, "witness.key")
	mustWriteKey(t, witnessKeyPath, witnessKey)
	originsPath := filepath.Join(dir, "origins.txt")
	if err := os.WriteFile(originsPath, []byte(originKey.VKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "checkpoint")
	cosignBin := mustFindCosignBinary(t)

	type issue struct {
		state    string
		comments []string
	}
	var (
		mu     sync.Mutex
		issues []*issue
	)

	// answer runs the request through the cosign binary and posts its
	// response, which is what the witness repository's workflow does.
	answer := func(number int, body string) {
		m := regexp.MustCompile("(?s)```http\n(.*?)```").FindStringSubmatch(body)
		if m == nil {
			t.Errorf("issue body carries no http block:\n%s", body)
			return
		}
		reqPath := filepath.Join(dir, fmt.Sprintf("request-%d", number))
		if err := os.WriteFile(reqPath, []byte(m[1]), 0644); err != nil {
			t.Error(err)
			return
		}
		out, err := exec.Command(cosignBin,
			"--request", reqPath,
			"--origin-vkeys", originsPath,
			"--key", witnessKeyPath,
			"--stored-checkpoint", statePath,
		).Output()
		if err != nil {
			t.Errorf("cosign: %v", err)
			return
		}

		mu.Lock()
		defer mu.Unlock()
		i := issues[number-1]
		i.comments = append(i.comments, "```http\n"+string(out)+"```")
		i.state = "closed"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Title, Body string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		issues = append(issues, &issue{state: "open"})
		n := len(issues)
		mu.Unlock()

		answer(n, in.Body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"number": n})
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues/{number}", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("number"))
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"state": issues[n-1].state})
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues/{number}/comments", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("number"))
		mu.Lock()
		defer mu.Unlock()
		out := []map[string]string{}
		for _, c := range issues[n-1].comments {
			out = append(out, map[string]string{"body": c})
		}
		_ = json.NewEncoder(w).Encode(out)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestIssueWitness checkpoints against a github-issue:// witness through
// git-ratchet's own transport, with no decomposed workflow: the checkpoint
// command opens the issue, waits for the reply and stores the result.
func TestIssueWitness(t *testing.T) {
	testIssueWitness(t, newFixture(t))
}

// TestIssueWitnessMLDSA runs the same exchange with ML-DSA-44 on both
// sides. signed-note gives 0x06 to the timestamped cosignature construction
// and nothing to a plain ML-DSA note signature, so a log signing its own
// checkpoint uses the byte a witness uses; this covers that both ends read it
// the same way.
func TestIssueWitnessMLDSA(t *testing.T) {
	testIssueWitness(t, newFixtureWithKeys(t, inote.MLDSA44, inote.MLDSA44))
}

func testIssueWitness(t *testing.T, f *fixture) {
	t.Helper()
	api := startIssueWitness(t, f.originKey, f.witnessKey)

	f.policyPath = writePolicyFile(t, f.repoDir, f.originKey, f.witnessKey,
		"github-issue://example-org/witness-repo")

	makeCommit(t, f.repoDir, "first commit")
	f.mustLogRefs(t, "refs/heads/main")
	if out, err := f.checkpointWithAPI(t, api); err != nil {
		t.Fatalf("checkpoint over the issue transport: %v\n%s", err, out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after checkpointing over issues: %v\n%s", err, out)
	}

	// A second round has to ratchet: the witness holds size 1 and the request
	// carries a consistency proof from there.
	makeCommit(t, f.repoDir, "second commit")
	f.mustLogRefs(t, "refs/heads/main")
	if out, err := f.checkpointWithAPI(t, api); err != nil {
		t.Fatalf("second checkpoint: %v\n%s", err, out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after the second round: %v\n%s", err, out)
	}
}

func mustFindBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GIT_RATCHET_BIN"); p != "" {
		return p
	}
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			p := filepath.Join(srcDir, ws, "git-ratchet_", "git-ratchet")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	t.Fatal("git-ratchet binary not found; run with: bazel test //e2e:e2e_test")
	return ""
}
func mustGenerateKey(t *testing.T, name string, sigType inote.SigType, role inote.KeyRole) *inote.Signer {
	t.Helper()
	s, err := inote.GenerateKey(name, sigType, role)
	if err != nil {
		t.Fatalf("generating key %s: %v", name, err)
	}
	return s
}

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "--initial-branch=main", ".")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	return dir
}

var e2eFileCounter int64

func makeCommit(t *testing.T, dir, msg string) string {
	t.Helper()
	n := atomic.AddInt64(&e2eFileCounter, 1)
	f := filepath.Join(dir, fmt.Sprintf("file-%d.txt", n))
	if err := os.WriteFile(f, []byte(msg+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", msg)
	out := runOutput(t, dir, "git", "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func writeKeyFile(t *testing.T, dir string, s *inote.Signer) string {
	t.Helper()
	p := filepath.Join(dir, "origin.key")
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(skey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustWriteKey(t *testing.T, path string, s *inote.Signer) {
	t.Helper()
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(skey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func runOutput(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s failed: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}
