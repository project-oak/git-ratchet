// Package e2e contains integration tests that exercise the git-ratchet CLI
// binary end-to-end, using a real git repo and a fake witness HTTP server.
package e2e

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
	"testing"

	"github.com/nickvidal/git-ratchet/internal/note"
)

// TestCheckpointBasic creates a git repo, runs git-ratchet checkpoint with
// a fake witness, and verifies the checkpoint ref exists with valid content.
func TestCheckpointBasic(t *testing.T) {
	binary := mustFindBinary(t)

	// Generate test keys.
	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	// Start a fake witness.
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	// Create a git repo with one commit.
	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	// Write the key and policy files.
	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	// Run: git-ratchet checkpoint
	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--commit", commitHash,
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
		"--origin", "test.example.com/repo",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("git-ratchet checkpoint failed: %v\n%s", err, out)
	}
	t.Logf("checkpoint output: %s", out)

	// Verify the checkpoint ref exists.
	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/main").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found: %v", err)
	}
	checkpoint := string(refOut)
	t.Logf("checkpoint content:\n%s", checkpoint)

	// Parse and verify the checkpoint.
	body, sigLines, err := note.ParseSignedNote(checkpoint)
	if err != nil {
		t.Fatalf("parsing checkpoint: %v", err)
	}

	// Check the body contains the expected origin and commit.
	expectedBody := "test.example.com/repo refs/heads/main\n" + commitHash + "\n"
	if body != expectedBody {
		t.Errorf("unexpected body:\ngot:  %q\nwant: %q", body, expectedBody)
	}

	// Should have 2 signature lines: origin + witness.
	if len(sigLines) != 2 {
		t.Fatalf("expected 2 signature lines, got %d: %v", len(sigLines), sigLines)
	}

	// Verify the origin signature.
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

	// Verify the witness cosignature.
	_, witnessPub, err := note.ParseVKey(witnessKey.VKey())
	if err != nil {
		t.Fatalf("parsing witness vkey: %v", err)
	}
	if err := note.VerifyCosignature(body, sigLines[1], witnessPub); err != nil {
		t.Errorf("witness cosignature invalid: %v", err)
	}
}

// TestCheckpointMultipleCommits verifies that checkpointing works after
// multiple commits, and that the checkpoint updates correctly.
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

	// 1. Checkpoint the first commit.
	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
		"--origin", "test.example.com/repo",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("first checkpoint failed: %v\n%s", err, out)
	}

	// 2. Make a second commit.
	secondHash := makeCommit(t, repoDir, "second commit")

	// 3. Checkpoint the second commit.
	// This should generate an ancestry proof spanning from firstHash to secondHash,
	// which the fake witness will verify and use to update its state.
	out, err = exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
		"--origin", "test.example.com/repo",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("second checkpoint failed: %v\n%s", err, out)
	}

	// Read and verify.
	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/main").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found: %v", err)
	}
	body, _, err := note.ParseSignedNote(string(refOut))
	if err != nil {
		t.Fatalf("parsing checkpoint: %v", err)
	}

	// Body should reference the second commit.
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

	// Start a witness that always returns 500.
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	// Checkpoint should fail because quorum is not met.
	out, err := exec.Command(binary,
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
		"--origin", "test.example.com/repo",
	).CombinedOutput()
	if err == nil {
		t.Fatalf("expected checkpoint to fail with insufficient witnesses, but it succeeded:\n%s", out)
	}
	if !strings.Contains(string(out), "insufficient cosignatures") {
		t.Errorf("expected 'insufficient cosignatures' error, got:\n%s", out)
	}
}

// --- Test helpers ---

func mustFindBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GIT_RATCHET_BIN"); p != "" {
		return p
	}
	// Bazel runfiles: TEST_SRCDIR/<workspace>/git-ratchet_/git-ratchet
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			p := filepath.Join(srcDir, ws, "git-ratchet_", "git-ratchet")
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	t.Fatal("git-ratchet binary not found; run with: bazel test //e2e:checkpoint_test")
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

func makeCommit(t *testing.T, dir, msg string) string {
	t.Helper()
	f := filepath.Join(dir, fmt.Sprintf("file-%d.txt", len(msg)))
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

func writePolicyFile(t *testing.T, dir string, origin, witness *note.Signer, witnessURL string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.txt")
	content := fmt.Sprintf("origin %s\nwitness %s %s\nquorum 1\n",
		origin.VKey(), witnessURL, witness.VKey())
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
	commits map[string]string // branchKey -> commit hash
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
	s := string(decoded)
	if !strings.HasPrefix(s, "commit ") {
		return "", fmt.Errorf("invalid commit prefix")
	}
	idx := strings.IndexByte(s, '\n')
	if idx < 0 {
		return "", fmt.Errorf("invalid format: missing newline")
	}
	header := s[:idx]
	content := s[idx+1:]

	var size int
	if _, err := fmt.Sscanf(header, "commit %d", &size); err != nil {
		return "", fmt.Errorf("parsing size: %w", err)
	}
	if size != len(content) {
		return "", fmt.Errorf("size mismatch: header %d, actual %d", size, len(content))
	}

	h := sha1.New()
	h.Write([]byte(fmt.Sprintf("commit %d\x00", size)))
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func newFakeWitness(t *testing.T, witnessKey *note.Signer, originKey *note.Signer) *fakeWitness {
	t.Helper()
	_, originPub, err := note.ParseVKey(originKey.VKey())
	if err != nil {
		t.Fatalf("parsing origin vkey: %v", err)
	}

	fw := &fakeWitness{
		commits: make(map[string]string),
	}

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

		// Split the body into ancestry proof and signed note.
		lines := strings.Split(bodyStr, "\n")
		var ancestry []string
		var signedNote string
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
		signedNote = strings.Join(lines[emptyLineIdx+1:], "\n")

		// Extract body and verify origin signature.
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

		// Parse body: "<origin> <ref>\n<commit-hash>\n"
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
			// Verify ancestry proof.
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

		// Update stored commit hash.
		fw.mu.Lock()
		fw.commits[branchKey] = newCommit
		fw.mu.Unlock()

		// Create cosignature.
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
