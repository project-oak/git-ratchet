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
	"sync/atomic"
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

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)
	witnessKey := mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner)

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
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, witnessURL, "refs/heads/main")

	// 1. Initial checkpoint — no ancestry required.
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath, commitHash1)
	refBody := readCheckpointRef(t, repoDir)
	if !strings.Contains(refBody, commitHash1) {
		t.Errorf("checkpoint 1: expected ref to contain %s", commitHash1)
	}
	if err := runVerify(t, gitRatchetBin, repoDir, policyPath); err != nil {
		t.Errorf("verify after checkpoint 1: %v", err)
	}

	// 2. Second commit — requires ancestry proof.
	commitHash2 := makeCommit(t, repoDir, "second commit")
	// HEAD is now ahead of checkpoint — verify should fail.
	if err := runVerify(t, gitRatchetBin, repoDir, policyPath); err == nil {
		t.Error("verify should fail when HEAD is ahead of checkpoint")
	}
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath, commitHash2)
	refBody = readCheckpointRef(t, repoDir)
	if !strings.Contains(refBody, commitHash2) {
		t.Errorf("checkpoint 2: expected ref to contain %s", commitHash2)
	}
	if err := runVerify(t, gitRatchetBin, repoDir, policyPath); err != nil {
		t.Errorf("verify after checkpoint 2: %v", err)
	}

	// 3. Restart server to verify state persistence.
	stopWitness()
	port3 := getFreePort(t)
	witnessURL3 := fmt.Sprintf("http://127.0.0.1:%d", port3)
	stopWitness3 := startWitnessServer(t, witnessBin, port3, witnessKeyPath, originsPath, statePath)
	defer stopWitness3()

	policyPath3 := writePolicyFile(t, repoDir, originKey, witnessKey, witnessURL3, "refs/heads/main")
	commitHash3 := makeCommit(t, repoDir, "third commit")
	runCheckpoint(t, gitRatchetBin, repoDir, clientKeyPath, policyPath3, commitHash3)
	if err := runVerify(t, gitRatchetBin, repoDir, policyPath3); err != nil {
		t.Errorf("verify after checkpoint 3: %v", err)
	}

	// 4. Tamper with the checkpoint blob — verify should reject it.
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
		t.Fatalf("updating ref to tampered blob: %v\n%s", err, out)
	}
	if err := runVerify(t, gitRatchetBin, repoDir, policyPath3); err == nil {
		t.Error("verify should fail after tampering with the checkpoint blob")
	}
}

// TestTagIntegration tests the tag checkpointing and immutability workflow.
func TestTagIntegration(t *testing.T) {
	gitRatchetBin := mustFindBinary(t)
	witnessBin := mustFindWitnessBinary(t)

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)
	witnessKey := mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner)

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

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
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, witnessURL, "refs/tags/v1.0.0")

	// 1. Checkpoint the tag.
	out, err := exec.Command(gitRatchetBin,
		"checkpoint",
		"--ref", "refs/tags/v1.0.0",
		"--repo", repoDir,
		"--key", clientKeyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("tag checkpoint failed: %v\n%s", err, out)
	}
	t.Logf("tag checkpoint: %s", out)

	// 2. Verify the tag checkpoint.
	out, err = exec.Command(gitRatchetBin,
		"verify",
		"--ref", "refs/tags/v1.0.0",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("tag verify failed: %v\n%s", err, out)
	}
	t.Logf("tag verify: %s", out)

	// 3. Confirm checkpoint ref is at the right path.
	refOut, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/tags/v1.0.0").Output()
	if err != nil {
		t.Fatalf("checkpoint ref not found at refs/checkpoints/tags/v1.0.0: %v", err)
	}
	if !strings.Contains(string(refOut), commitHash) {
		t.Errorf("checkpoint body should contain commit %s", commitHash)
	}

	// 4. Move the tag — verify should fail.
	_ = makeCommit(t, repoDir, "new commit")
	run(t, repoDir, "git", "tag", "-f", "v1.0.0")

	out, err = exec.Command(gitRatchetBin,
		"verify",
		"--ref", "refs/tags/v1.0.0",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatal("verify should fail after tag was moved")
	}
	t.Logf("verify after tag move (expected failure): %s", out)

	// 5. Second checkpoint for the moved tag — witness should reject with 409.
	out, err = exec.Command(gitRatchetBin,
		"checkpoint",
		"--ref", "refs/tags/v1.0.0",
		"--repo", repoDir,
		"--key", clientKeyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err == nil {
		t.Fatal("second checkpoint should fail for moved tag")
	}
	t.Logf("second tag checkpoint (expected failure): %s", out)
}

// runVerify invokes git-ratchet verify and returns any error (nil = exit 0).
func runVerify(t *testing.T, binary, repoDir, policyPath string) error {
	t.Helper()
	out, err := exec.Command(binary,
		"verify",
		"--ref", "refs/heads/main",
		"--repo", repoDir,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Logf("verify output: %s", out)
	}
	return err
}

// runCheckpoint invokes git-ratchet checkpoint and fatals on failure.
func runCheckpoint(t *testing.T, binary, repoDir, keyPath, policyPath, commit string) {
	t.Helper()
	args := []string{
		"checkpoint",
		"--ref", "refs/heads/main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	}
	out, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("git-ratchet checkpoint failed: %v\n%s", err, out)
	}
}

// readCheckpointRef reads the refs/checkpoints/heads/main blob and returns its content.
func readCheckpointRef(t *testing.T, repoDir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repoDir, "cat-file", "-p", "refs/checkpoints/heads/main").Output()
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

func mustGenerateKey(t *testing.T, name string, sigType note.SigType, role note.KeyRole) *note.Signer {
	t.Helper()
	s, err := note.GenerateKey(name, sigType, role)
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

func writeKeyFile(t *testing.T, dir string, s *note.Signer) string {
	t.Helper()
	p := filepath.Join(dir, "origin.key")
	content := s.VKey() + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustWriteKey(t *testing.T, path string, s *note.Signer) {
	t.Helper()
	content := s.VKey() + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func writePolicyFile(t *testing.T, dir string, log, witness *note.Signer, witnessURL string, refs ...string) string {
	t.Helper()
	p := filepath.Join(dir, "policy.txt")
	var b strings.Builder
	fmt.Fprintf(&b, "log %s\n", log.VKey())
	for _, ref := range refs {
		fmt.Fprintf(&b, "ref %s\n", ref)
	}
	fmt.Fprintf(&b, "witness w1 %s %s\nquorum w1\n", witnessURL, witness.VKey())
	if err := os.WriteFile(p, []byte(b.String()), 0644); err != nil {
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
	waitForServer(t, fmt.Sprintf("127.0.0.1:%d", port))
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// waitForServer polls addr ("host:port") until a TCP connection succeeds or the
// deadline (5 s) is exceeded, using exponential backoff starting at 5 ms.
func waitForServer(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	delay := 5 * time.Millisecond
	for {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("witness server at %s did not start within 5s: %v", addr, err)
		}
		time.Sleep(delay)
		if delay < 200*time.Millisecond {
			delay *= 2
		}
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
