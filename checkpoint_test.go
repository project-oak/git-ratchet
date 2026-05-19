// Package main_test exercises the git-ratchet CLI binary against an in-process
// fake witness server, verifying the basic checkpoint workflow.
package main_test

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/BenBirt/git-ratchet/internal/gitutil"
	"github.com/BenBirt/git-ratchet/internal/note"
)

// TestCheckpointBasic creates a git repo, runs git-ratchet checkpoint with
// a fake witness, and verifies the checkpoint ref exists with valid content.
func TestCheckpointBasic(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--commit", commitHash,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("git-ratchet checkpoint failed: %v\n%s", err, out)
	}
	t.Logf("checkpoint output: %s", out)

	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/heads/main").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found: %v", err)
	}
	checkpoint := string(refOut)
	t.Logf("checkpoint content:\n%s", checkpoint)

	body, sigLines, err := note.ParseSignedNote(checkpoint)
	if err != nil {
		t.Fatalf("parsing checkpoint: %v", err)
	}

	expectedBody := originKey.Name + " refs/heads/main\n" + commitHash + "\n"
	if body != expectedBody {
		t.Errorf("unexpected body:\ngot:  %q\nwant: %q", body, expectedBody)
	}

	if len(sigLines) != 2 {
		t.Fatalf("expected 2 signature lines, got %d: %v", len(sigLines), sigLines)
	}

	originName, originPub, err := note.ParseVKey(originKey.VKey())
	if err != nil {
		t.Fatalf("parsing origin vkey: %v", err)
	}
	originSigName, err := note.SigName(sigLines[0])
	if err != nil {
		t.Fatalf("extracting origin sig name: %v", err)
	}
	if originSigName != originName {
		t.Errorf("origin sig name: got %q, want %q", originSigName, originName)
	}
	if err := note.VerifySignature(body, sigLines[0], originPub); err != nil {
		t.Errorf("origin signature invalid: %v", err)
	}

	_, witnessPub, err := note.ParseVKey(witnessKey.VKey())
	if err != nil {
		t.Fatalf("parsing witness vkey: %v", err)
	}
	if err := note.VerifyCosignature(body, sigLines[1], witnessPub); err != nil {
		t.Errorf("witness cosignature invalid: %v", err)
	}
}

// TestCheckpointMultipleCommits verifies that sequential checkpoints work
// correctly, with the second requiring an ancestry proof.
func TestCheckpointMultipleCommits(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "first commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("first checkpoint failed: %v\n%s", err, out)
	}

	secondHash := makeCommit(t, repoDir, "second commit")

	out, err = exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("second checkpoint failed: %v\n%s", err, out)
	}

	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/heads/main").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found: %v", err)
	}
	body, _, err := note.ParseSignedNote(string(refOut))
	if err != nil {
		t.Fatalf("parsing checkpoint: %v", err)
	}

	if !strings.Contains(body, secondHash) {
		t.Errorf("checkpoint body should contain commit %s, got:\n%s", secondHash, body)
	}
}

// TestCheckpointInsufficientWitnesses verifies that the command fails when
// quorum is not met.
func TestCheckpointInsufficientWitnesses(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected checkpoint to fail with insufficient witnesses, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "insufficient cosignatures") {
		t.Errorf("expected 'insufficient cosignatures' error, got:\n%s", out)
	}
}

// TestVerifyBasic checkpoints a branch and then verifies it, expecting success.
func TestVerifyBasic(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--commit", commitHash,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}

	out, err = exec.Command(binary,
		"verify",
		"--branch", "main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	t.Logf("verify output: %s", out)
}

// TestVerifyNoCheckpoint verifies that a missing checkpoint ref produces a
// non-zero exit and includes a git fetch hint in the error output.
func TestVerifyNoCheckpoint(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "initial commit")

	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, "http://unused")

	out, err := exec.Command(binary,
		"verify",
		"--branch", "main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail with no checkpoint, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "git fetch") {
		t.Errorf("expected git fetch hint in error output, got:\n%s", out)
	}
}

// TestVerifyAheadOfCheckpoint makes two commits, checkpoints at the first,
// then verifies when HEAD is at the second (unwitnessed) commit.
// verify should fail because HEAD is ahead of the checkpoint.
func TestVerifyAheadOfCheckpoint(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitA := makeCommit(t, repoDir, "first commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	// Checkpoint at commit A.
	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--commit", commitA,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}

	// Advance HEAD to commit B (unwitnessed).
	_ = makeCommit(t, repoDir, "second commit not yet witnessed")

	out, err = exec.Command(binary,
		"verify",
		"--branch", "main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when HEAD is ahead of checkpoint, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "ahead of") {
		t.Errorf("expected 'ahead of' in error output, got:\n%s", out)
	}
}

// TestVerifyTamperedNote checkpoints a branch then overwrites the checkpoint
// blob with a note whose bytes have been corrupted. verify should fail.
func TestVerifyTamperedNote(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--commit", commitHash,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}

	// Read the checkpoint and corrupt bytes near the end of the signature blob.
	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/heads/main").Output()
	if err != nil {
		t.Fatalf("reading checkpoint ref: %v", err)
	}
	tampered := []byte(string(refOut))
	for i := len(tampered) - 5; i < len(tampered)-1; i++ {
		tampered[i] ^= 0xFF
	}
	hashCmd := exec.Command("git", "-C", repoDir, "hash-object", "-w", "--stdin")
	hashCmd.Stdin = strings.NewReader(string(tampered))
	blobOut, err := hashCmd.Output()
	if err != nil {
		t.Fatalf("writing tampered blob: %v", err)
	}
	blobHash := strings.TrimSpace(string(blobOut))
	if out, err := exec.Command("git", "-C", repoDir, "update-ref",
		"refs/checkpoints/heads/main", blobHash).CombinedOutput(); err != nil {
		t.Fatalf("updating ref: %v\n%s", err, out)
	}

	out, err = exec.Command(binary,
		"verify",
		"--branch", "main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail with tampered note, but it succeeded:\n%s", out)
	}
	t.Logf("verify error (expected): %s", out)
}

// TestVerifyInsufficientCosigs stores a note with only an origin signature
// (no witness cosigs) and expects verify to fail the quorum check.
func TestVerifyInsufficientCosigs(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, "http://unused")

	// Build a note with only the origin (log) signature — no cosig.
	body := originKey.Name + " refs/heads/main\n" + commitHash + "\n"
	signed, err := note.Sign(body, originKey)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}
	hashCmd := exec.Command("git", "-C", repoDir, "hash-object", "-w", "--stdin")
	hashCmd.Stdin = strings.NewReader(signed)
	blobOut, err := hashCmd.Output()
	if err != nil {
		t.Fatalf("writing blob: %v", err)
	}
	blobHash := strings.TrimSpace(string(blobOut))
	if out, err := exec.Command("git", "-C", repoDir, "update-ref",
		"refs/checkpoints/heads/main", blobHash).CombinedOutput(); err != nil {
		t.Fatalf("updating ref: %v\n%s", err, out)
	}

	out, err := exec.Command(binary,
		"verify",
		"--branch", "main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail with no cosignatures, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "insufficient cosignatures") {
		t.Errorf("expected 'insufficient cosignatures' in error output, got:\n%s", out)
	}
}

// TestTagCheckpointBasic creates a git repo with a tag, checkpoints it,
// and verifies the checkpoint ref exists at refs/checkpoints/tags/<name>.
func TestTagCheckpointBasic(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("git-ratchet checkpoint --tag failed: %v\n%s", err, out)
	}
	t.Logf("checkpoint output: %s", out)

	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/tags/v1.0.0").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found at refs/checkpoints/tags/v1.0.0: %v", err)
	}
	checkpoint := string(refOut)

	body, sigLines, err := note.ParseSignedNote(checkpoint)
	if err != nil {
		t.Fatalf("parsing checkpoint: %v", err)
	}

	expectedBody := originKey.Name + " refs/tags/v1.0.0\n" + commitHash + "\n"
	if body != expectedBody {
		t.Errorf("unexpected body:\ngot:  %q\nwant: %q", body, expectedBody)
	}

	if len(sigLines) != 2 {
		t.Fatalf("expected 2 signature lines, got %d: %v", len(sigLines), sigLines)
	}
}

// TestTagVerifyBasic checkpoints a tag and then verifies it.
func TestTagVerifyBasic(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--tag", "v1.0.0",
		"--commit", commitHash,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}

	out, err = exec.Command(binary,
		"verify",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	t.Logf("verify output: %s", out)
}

// TestTagVerifyMoved checkpoints a tag, moves it to a different commit,
// and verifies that verify detects the tag has been moved.
func TestTagVerifyMoved(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	out, err := exec.Command(binary,
		"checkpoint",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint failed: %v\n%s", err, out)
	}

	// Move the tag to a different commit.
	_ = makeCommit(t, repoDir, "new commit")
	run(t, repoDir, "git", "tag", "-f", "v1.0.0")

	out, err = exec.Command(binary,
		"verify",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected verify to fail when tag has been moved, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "tag does not match checkpoint") {
		t.Errorf("expected 'tag does not match checkpoint' in error output, got:\n%s", out)
	}
}

// TestTagCheckpointImmutability checkpoints a tag, moves it, and verifies
// that the witness rejects a second checkpoint for the moved tag.
func TestTagCheckpointImmutability(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	// First checkpoint — should succeed.
	out, err := exec.Command(binary,
		"checkpoint",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("first checkpoint failed: %v\n%s", err, out)
	}

	// Move the tag to a different commit.
	_ = makeCommit(t, repoDir, "different commit")
	run(t, repoDir, "git", "tag", "-f", "v1.0.0")

	// Second checkpoint — should fail because witness rejects immutability violation.
	out, err = exec.Command(binary,
		"checkpoint",
		"--tag", "v1.0.0",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected second checkpoint to fail after tag was moved, but it succeeded:\n%s", out)
	}
	t.Logf("second checkpoint error (expected): %s", out)
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
	t.Fatal("git-ratchet binary not found; run with: bazel test //:checkpoint_test")
	return ""
}

func mustGenerateKey(t *testing.T, name string) *note.Signer {
	t.Helper()
	s, err := note.GenerateKey(name)
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

var testFileCounter int64

func makeCommit(t *testing.T, dir, msg string) string {
	t.Helper()
	n := atomic.AddInt64(&testFileCounter, 1)
	f := filepath.Join(dir, fmt.Sprintf("file-%d.txt", n))
	if err := os.WriteFile(f, []byte(msg+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", msg)
	out := runOutput(t, dir, "git", "rev-parse", "HEAD")
	return strings.TrimSpace(out)
}

func writeKeyFile(t *testing.T, dir string, s *note.Signer) string {
	t.Helper()
	p := filepath.Join(dir, "origin.key")
	content := s.Name + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writePolicyFile(t *testing.T, dir string, log, witness *note.Signer, witnessURL string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.txt")
	// tlog-policy format: log, named witness (w1), quorum referencing the witness by name.
	content := fmt.Sprintf("log %s\nwitness w1 %s %s\nquorum w1\n",
		log.VKey(), witnessURL, witness.VKey())
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
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

// --- Fake witness ---

type fakeWitness struct {
	*httptest.Server
	mu      sync.Mutex
	commits map[string]string
}

func parseParent(commitContent string) string {
	for _, line := range strings.Split(commitContent, "\n") {
		if strings.HasPrefix(line, "parent ") {
			return strings.TrimPrefix(line, "parent ")
		}
	}
	return ""
}

func gitCommitHash(decoded []byte) (string, error) {
	return gitutil.CommitHash(decoded, sha1.Size*2) // SHA-1: 40 hex chars
}

func newFakeWitness(t *testing.T, witnessKey *note.Signer, originKey *note.Signer) *fakeWitness {
	t.Helper()
	_, originPub, err := note.ParseVKey(originKey.VKey())
	if err != nil {
		t.Fatalf("parsing origin vkey: %v", err)
	}

	fw := &fakeWitness{commits: make(map[string]string)}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/add-checkpoint" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		bodyStr := string(bodyBytes)

		lines := strings.Split(bodyStr, "\n")
		var ancestry []string
		emptyLineIdx := -1
		for i, line := range lines {
			if line == "" {
				emptyLineIdx = i
				break
			}
			ancestry = append(ancestry, line)
		}
		if emptyLineIdx < 0 {
			http.Error(w, "malformed request: missing empty line separator", http.StatusBadRequest)
			return
		}
		signedNote := strings.Join(lines[emptyLineIdx+1:], "\n")

		noteBody, sigLines, err := note.ParseSignedNote(signedNote)
		if err != nil {
			http.Error(w, fmt.Sprintf("parse error: %v", err), http.StatusBadRequest)
			return
		}
		if len(sigLines) == 0 {
			http.Error(w, "no origin signature", http.StatusBadRequest)
			return
		}
		if err := note.VerifySignature(noteBody, sigLines[0], originPub); err != nil {
			http.Error(w, fmt.Sprintf("origin signature invalid: %v", err), http.StatusForbidden)
			return
		}

		bodyLines := strings.Split(strings.TrimSpace(noteBody), "\n")
		if len(bodyLines) < 2 {
			http.Error(w, "malformed checkpoint body", http.StatusBadRequest)
			return
		}
		branchParts := strings.Fields(bodyLines[0])
		if len(branchParts) != 2 {
			http.Error(w, "malformed branch line", http.StatusBadRequest)
			return
		}
		branchKey := branchParts[0] + " " + branchParts[1]
		newCommit := strings.TrimSpace(bodyLines[1])

		fw.mu.Lock()
		storedCommit := fw.commits[branchKey]
		fw.mu.Unlock()

		if storedCommit != "" && newCommit != storedCommit {
			// Check if this is a tag ref — tags are immutable.
			if strings.HasPrefix(branchParts[1], "refs/tags/") {
				http.Error(w, "tag checkpoint rejected: tags are immutable", http.StatusConflict)
				return
			}
			commitMap := make(map[string]string)
			for _, b64Obj := range ancestry {
				decoded, err := base64.StdEncoding.DecodeString(b64Obj)
				if err != nil {
					http.Error(w, "malformed base64 in ancestry", http.StatusUnprocessableEntity)
					return
				}
				commitID, err := gitCommitHash(decoded)
				if err != nil {
					http.Error(w, "invalid commit object in ancestry", http.StatusUnprocessableEntity)
					return
				}
				s := string(decoded)
				idx := strings.IndexByte(s, '\n')
				commitMap[commitID] = s[idx+1:]
			}

			curr := newCommit
			for curr != storedCommit {
				content, ok := commitMap[curr]
				if !ok {
					http.Error(w, "incomplete ancestry proof", http.StatusUnprocessableEntity)
					return
				}
				parent := parseParent(content)
				if parent == "" {
					http.Error(w, "broken ancestry proof chain", http.StatusUnprocessableEntity)
					return
				}
				curr = parent
			}
		}

		fw.mu.Lock()
		fw.commits[branchKey] = newCommit
		fw.mu.Unlock()

		cosigLine, err := note.Cosign(signedNote, witnessKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("cosign error: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, cosigLine)
	}))

	fw.Server = srv
	return fw
}
