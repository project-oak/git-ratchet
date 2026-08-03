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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
)

// tlogFixture is a repository wired up to a running tlog-mode witness.
type tlogFixture struct {
	ratchetBin string
	repoDir    string
	keyPath    string
	policyPath string

	witnessBin  string
	witnessKey  *note.Signer
	originKey   *note.Signer
	originsPath string
	statePath   string
}

func newTlogFixture(t *testing.T) *tlogFixture {
	t.Helper()

	f := &tlogFixture{
		ratchetBin: mustFindBinary(t),
		witnessBin: mustFindWitnessBinary(t),
		originKey:  mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin),
		witnessKey: mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner),
	}
	f.repoDir = initTestRepo(t)

	tmpDir := t.TempDir()
	witnessKeyPath := filepath.Join(tmpDir, "witness.key")
	mustWriteKey(t, witnessKeyPath, f.witnessKey)

	f.originsPath = filepath.Join(tmpDir, "origins.txt")
	if err := os.WriteFile(f.originsPath, []byte(f.originKey.VKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	f.statePath = filepath.Join(tmpDir, "state.json")
	f.keyPath = writeKeyFile(t, tmpDir, f.originKey)

	port := getFreePort(t)
	stop := startTlogWitnessServer(t, f.witnessBin, port, witnessKeyPath, f.originsPath, f.statePath)
	t.Cleanup(stop)

	f.policyPath = writePolicyFile(t, f.repoDir, f.originKey, f.witnessKey,
		fmt.Sprintf("http://127.0.0.1:%d", port))
	return f
}

// startTlogWitnessServer starts the witness binary in transparency-log mode.
func startTlogWitnessServer(t *testing.T, binary string, port int, keyPath, originsPath, statePath string) func() {
	t.Helper()
	cmd := exec.Command(binary,
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-mode", "tlog",
		"-key", keyPath,
		"-origins-file", originsPath,
		"-state-file", statePath,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tlog witness server: %v", err)
	}
	waitForServer(t, fmt.Sprintf("127.0.0.1:%d", port))
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// checkpoint runs git-ratchet checkpoint in tlog mode, returning its output.
func (f *tlogFixture) checkpoint(t *testing.T, ref string) (string, error) {
	t.Helper()
	out, err := exec.Command(f.ratchetBin,
		"checkpoint",
		"--mode", "tlog",
		"--ref", ref,
		"--repo", f.repoDir,
		"--key", f.keyPath,
		"--policy", f.policyPath,
	).CombinedOutput()
	return string(out), err
}

func (f *tlogFixture) mustCheckpoint(t *testing.T, ref string) string {
	t.Helper()
	out, err := f.checkpoint(t, ref)
	if err != nil {
		t.Fatalf("checkpoint %s failed: %v\n%s", ref, err, out)
	}
	return out
}

// verify runs git-ratchet verify in tlog mode, returning its output.
func (f *tlogFixture) verify(t *testing.T, refs ...string) (string, error) {
	t.Helper()
	args := []string{"verify", "--mode", "tlog", "--repo", f.repoDir, "--policy", f.policyPath}
	for _, ref := range refs {
		args = append(args, "--ref", ref)
	}
	out, err := exec.Command(f.ratchetBin, args...).CombinedOutput()
	return string(out), err
}

// TestTlogIntegration walks the happy path: successive fast-forward commits are
// logged, cosigned, and verify cleanly.
func TestTlogIntegration(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.mustCheckpoint(t, "refs/heads/main")
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after first checkpoint: %v\n%s", err, out)
	}

	// A commit that has not been logged leaves the branch ahead of the log.
	makeCommit(t, f.repoDir, "second commit")
	if out, err := f.verify(t, "refs/heads/main"); err == nil {
		t.Errorf("verify should fail while HEAD is ahead of the log:\n%s", out)
	}

	f.mustCheckpoint(t, "refs/heads/main")
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after second checkpoint: %v\n%s", err, out)
	}

	makeCommit(t, f.repoDir, "third commit")
	out := f.mustCheckpoint(t, "refs/heads/main")
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

// TestTlogRecheckpointUnchangedRefDoesNotGrowLog checks that re-checkpointing a
// ref that has not moved refreshes cosignatures without appending a redundant
// entry.
func TestTlogRecheckpointUnchangedRefDoesNotGrowLog(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "only commit")
	f.mustCheckpoint(t, "refs/heads/main")

	out := f.mustCheckpoint(t, "refs/heads/main")
	if !strings.Contains(out, "log size 1") {
		t.Errorf("re-checkpointing an unchanged ref should leave the log at size 1, got: %s", out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after refresh: %v\n%s", err, out)
	}
}

// TestTlogDetectsBranchRollback is the central test for this mode.
//
// The witness only attests that the log grew by appending, so it cosigns a
// rollback quite happily — there is nothing in a consistency proof that says
// anything about Git ancestry. The property is preserved because verify walks
// the logged entries and finds that one does not descend from its predecessor.
func TestTlogDetectsBranchRollback(t *testing.T) {
	f := newTlogFixture(t)

	first := makeCommit(t, f.repoDir, "first commit")
	makeCommit(t, f.repoDir, "second commit")
	f.mustCheckpoint(t, "refs/heads/main")
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify before rollback: %v\n%s", err, out)
	}

	// Roll the branch back and log the rolled-back state.
	run(t, f.repoDir, "git", "reset", "--hard", first)

	out, err := f.checkpoint(t, "refs/heads/main")
	if err != nil {
		t.Fatalf("the witness is expected to cosign a rollback in tlog mode, "+
			"since appending to the log is consistent: %v\n%s", err, out)
	}

	verifyOut, err := f.verify(t, "refs/heads/main")
	if err == nil {
		t.Fatalf("verify should reject a logged rollback:\n%s", verifyOut)
	}
	if !strings.Contains(verifyOut, "history was rewritten") {
		t.Errorf("expected a rewritten-history diagnostic, got:\n%s", verifyOut)
	}
}

// TestTlogDetectsTagMove checks the create-once rule for tags: a tag logged
// twice is a moved tag, whatever it points at.
func TestTlogDetectsTagMove(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	run(t, f.repoDir, "git", "tag", "v1.0.0")
	f.mustCheckpoint(t, "refs/tags/v1.0.0")
	if out, err := f.verify(t, "refs/tags/v1.0.0"); err != nil {
		t.Fatalf("verify after tagging: %v\n%s", err, out)
	}

	// Move the tag and log it again.
	makeCommit(t, f.repoDir, "second commit")
	run(t, f.repoDir, "git", "tag", "-f", "v1.0.0")

	if out, err := f.checkpoint(t, "refs/tags/v1.0.0"); err != nil {
		t.Fatalf("the witness is expected to cosign a moved tag in tlog mode: %v\n%s", err, out)
	}

	verifyOut, err := f.verify(t, "refs/tags/v1.0.0")
	if err == nil {
		t.Fatalf("verify should reject a tag logged twice:\n%s", verifyOut)
	}
	if !strings.Contains(verifyOut, "must be logged exactly once") {
		t.Errorf("expected a create-once diagnostic, got:\n%s", verifyOut)
	}
}

// TestTlogVerifyRejectsUnloggedRef checks that a ref with no entries is not
// silently treated as verified.
func TestTlogVerifyRejectsUnloggedRef(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.mustCheckpoint(t, "refs/heads/main")

	run(t, f.repoDir, "git", "branch", "other")
	out, err := f.verify(t, "refs/heads/other")
	if err == nil {
		t.Fatalf("verify should reject a ref with no log entries:\n%s", out)
	}
	if !strings.Contains(out, "no log entries") {
		t.Errorf("expected a no-entries diagnostic, got:\n%s", out)
	}
}

// TestTlogVerifyRejectsTamperedCheckpoint checks that the stored checkpoint's
// signature is actually enforced.
func TestTlogVerifyRejectsTamperedCheckpoint(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.mustCheckpoint(t, "refs/heads/main")

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

// TestTlogWitnessSizeConflictRecovery checks the 409 recovery path: a witness
// that has lost its state reports the size it actually holds, and the client
// regenerates its proof and resubmits without operator intervention.
func TestTlogWitnessSizeConflictRecovery(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	f.mustCheckpoint(t, "refs/heads/main")
	makeCommit(t, f.repoDir, "second commit")
	f.mustCheckpoint(t, "refs/heads/main")

	// Wipe the witness's state and restart it on a new port. The client still
	// believes the witness holds a tree of size 2.
	if err := os.Remove(f.statePath); err != nil {
		t.Fatal(err)
	}
	witnessKeyPath := filepath.Join(t.TempDir(), "witness.key")
	mustWriteKey(t, witnessKeyPath, f.witnessKey)
	port := getFreePort(t)
	stop := startTlogWitnessServer(t, f.witnessBin, port, witnessKeyPath, f.originsPath, f.statePath)
	defer stop()
	f.policyPath = writePolicyFile(t, f.repoDir, f.originKey, f.witnessKey,
		fmt.Sprintf("http://127.0.0.1:%d", port))

	makeCommit(t, f.repoDir, "third commit")
	if out, err := f.checkpoint(t, "refs/heads/main"); err != nil {
		t.Fatalf("checkpoint should recover from a witness size conflict: %v\n%s", err, out)
	}
	if out, err := f.verify(t, "refs/heads/main"); err != nil {
		t.Fatalf("verify after conflict recovery: %v\n%s", err, out)
	}
}

// TestTlogMultipleRefsShareOneLog checks that branches and tags coexist in a
// single log and are each verified against their own entries.
func TestTlogMultipleRefsShareOneLog(t *testing.T) {
	f := newTlogFixture(t)

	makeCommit(t, f.repoDir, "first commit")
	run(t, f.repoDir, "git", "tag", "v1.0.0")
	f.mustCheckpoint(t, "refs/heads/main")
	f.mustCheckpoint(t, "refs/tags/v1.0.0")

	makeCommit(t, f.repoDir, "second commit")
	out := f.mustCheckpoint(t, "refs/heads/main")
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
