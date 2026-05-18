// Package e2e contains end-to-end tests that exercise the git-ratchet CLI
// and the witness server binary working together against real git repositories.
package e2e

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BenBirt/git-ratchet/internal/note"
)

// TestIntegration runs the git-ratchet CLI against the real witness server,
// verifying initial checkpointing, ancestry proofs, and state persistence
// across a server restart.
func TestIntegration(t *testing.T) {
	gitRatchetBin := mustFindBinary(t)
	witnessBin := mustFindWitnessBinary(t)

	originKey := mustGenerateKey(t, "test-origin")
	witnessKey := mustGenerateKey(t, "test-witness")

	repoDir := initTestRepo(t)
	commitHash1 := makeCommit(t, repoDir, "initial commit")

	tmpDir := t.TempDir()
	witnessKeyPath := filepath.Join(tmpDir, "witness.key")
	mustWriteKey(t, witnessKeyPath, witnessKey)

	originsPath := filepath.Join(tmpDir, "origins.txt")
	if err := os.WriteFile(originsPath, []byte(originKey.VKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(tmpDir, "state.json")

	port := getFreePort(t)
	witnessURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	stopWitness := startWitnessServer(t, witnessBin, port, witnessKeyPath, originsPath, statePath)
	defer stopWitness()

	clientKeyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, witnessURL)

	// 1. Initial checkpoint — no ancestry required.
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath, commitHash1)
	refBody := readCheckpointRef(t, repoDir)
	if !strings.Contains(refBody, commitHash1) {
		t.Errorf("checkpoint 1: expected ref to contain %s", commitHash1)
	}

	// 2. Second commit — requires ancestry proof.
	commitHash2 := makeCommit(t, repoDir, "second commit")
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath, commitHash2)
	refBody = readCheckpointRef(t, repoDir)
	if !strings.Contains(refBody, commitHash2) {
		t.Errorf("checkpoint 2: expected ref to contain %s", commitHash2)
	}

	// 3. Restart server to verify state persistence.
	stopWitness()
	port3 := getFreePort(t)
	witnessURL3 := fmt.Sprintf("http://127.0.0.1:%d", port3)
	stopWitness3 := startWitnessServer(t, witnessBin, port3, witnessKeyPath, originsPath, statePath)
	defer stopWitness3()

	policyPath3 := writePolicyFile(t, repoDir, originKey, witnessKey, witnessURL3)
	commitHash3 := makeCommit(t, repoDir, "third commit")
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath3, commitHash3)
}

// runCheckpoint invokes git-ratchet checkpoint and fatals on failure.
func runCheckpoint(t *testing.T, binary, repoDir, keyPath, policyPath, commit string) {
	t.Helper()
	args := []string{
		"checkpoint",
		"--branch", "main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
		"--origin", "test.example.com/repo",
	}
	if commit != "" {
		args = append(args, "--commit", commit)
	}
	out, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git-ratchet checkpoint failed: %v\n%s", err, out)
	}
}

// readCheckpointRef reads the refs/checkpoints/main blob and returns its content.
func readCheckpointRef(t *testing.T, repoDir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/main").Output()
	if err != nil {
		t.Fatalf("reading checkpoint ref: %v", err)
	}
	return string(out)
}

// --- Helpers ---

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

func mustFindWitnessBinary(t *testing.T) string {
	t.Helper()
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "witness", "witness_", "witness"),
				filepath.Join(srcDir, ws, "witness", "witness"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("witness binary not found; run with: bazel test //e2e:e2e_test")
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

func mustWriteKey(t *testing.T, path string, s *note.Signer) {
	t.Helper()
	content := s.Name + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
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

func getFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startWitnessServer(t *testing.T, binary string, port int, keyPath, originsPath, statePath string) func() {
	t.Helper()
	cmd := exec.Command(binary,
		"-addr", fmt.Sprintf("127.0.0.1:%d", port),
		"-key", keyPath,
		"-origins-file", originsPath,
		"-state-file", statePath,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting witness server: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
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
