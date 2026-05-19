// Package main tests the witness HTTP server by hitting the /add-checkpoint
// endpoint directly with crafted payloads, without going through the git-ratchet
// client. This exercises the server's own request-parsing and validation logic.
package main_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BenBirt/git-ratchet/internal/note"
)

// mustFindWitnessBinary locates the compiled witness binary from Bazel runfiles.
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
	t.Fatal("witness binary not found; run with: bazel test //witness:server_test")
	return ""
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

func mustGenerateKey(t *testing.T, name string, sigType note.SigType, role note.KeyRole) *note.Signer {
	t.Helper()
	s, err := note.GenerateKey(name, sigType, role)
	if err != nil {
		t.Fatalf("generating key %s: %v", name, err)
	}
	return s
}

func mustWriteKey(t *testing.T, path string, s *note.Signer) {
	t.Helper()
	content := s.VKey() + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// startWitnessServer starts the witness binary and returns its base URL and a stop function.
func startWitnessServer(t *testing.T, binary string, port int, keyPath, originsPath, statePath string) (string, func()) {
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
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	return url, func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// makeSignedCheckpoint builds and signs a checkpoint note for the given origin/ref/commit.
func makeSignedCheckpoint(t *testing.T, signer *note.Signer, origin, ref, commit string) string {
	t.Helper()
	body := origin + " " + ref + "\n" + commit + "\n"
	signed, err := note.Sign(body, signer)
	if err != nil {
		t.Fatalf("signing checkpoint: %v", err)
	}
	return signed
}

// post sends a POST /add-checkpoint request and returns the response.
func post(t *testing.T, baseURL, payload string) *http.Response {
	t.Helper()
	resp, err := http.Post(baseURL+"/add-checkpoint", "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /add-checkpoint: %v", err)
	}
	return resp
}

// readBody reads and trims the response body.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return strings.TrimSpace(string(b))
}

// setupServer starts a witness server for a single test and returns its URL,
// the origin signer, and a stop function.
func setupServer(t *testing.T) (baseURL string, originKey, witnessKey *note.Signer, stop func()) {
	t.Helper()
	bin := mustFindWitnessBinary(t)
	originKey = mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)
	witnessKey = mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner)

	tmpDir := t.TempDir()
	witnessKeyPath := filepath.Join(tmpDir, "witness.key")
	mustWriteKey(t, witnessKeyPath, witnessKey)

	originsPath := filepath.Join(tmpDir, "origins.txt")
	if err := os.WriteFile(originsPath, []byte(originKey.VKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(tmpDir, "state.json")
	port := getFreePort(t)
	baseURL, stop = startWitnessServer(t, bin, port, witnessKeyPath, originsPath, statePath)
	return
}

// TestAddCheckpointFirstSubmission verifies that a fresh (uninitialized) branch
// is accepted without any ancestry proof and returns a valid cosignature.
func TestAddCheckpointFirstSubmission(t *testing.T) {
	baseURL, originKey, witnessKey, stop := setupServer(t)
	defer stop()

	commit := strings.Repeat("a", 40)
	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed // empty ancestry + separator

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(body, note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", body)
	}

	_, _, witnessPub, err := note.ParseVKey(witnessKey.VKey())
	if err != nil {
		t.Fatalf("parsing witness vkey: %v", err)
	}
	noteBody := "example.com/repo refs/heads/main\n" + commit + "\n"
	if err := note.VerifyCosignature(noteBody, body, witnessPub, note.Ed25519Cosigner, "test-witness"); err != nil {
		t.Errorf("cosignature verification failed: %v", err)
	}
}

// TestAddCheckpointFirstSubmissionSHA256 is the SHA-256 variant of
// TestAddCheckpointFirstSubmission.
func TestAddCheckpointFirstSubmissionSHA256(t *testing.T) {
	baseURL, originKey, witnessKey, stop := setupServer(t)
	defer stop()

	commit := strings.Repeat("a", 64) // SHA-256 length
	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(body, note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", body)
	}

	_, _, witnessPub, err := note.ParseVKey(witnessKey.VKey())
	if err != nil {
		t.Fatalf("parsing witness vkey: %v", err)
	}
	noteBody := "example.com/repo refs/heads/main\n" + commit + "\n"
	if err := note.VerifyCosignature(noteBody, body, witnessPub, note.Ed25519Cosigner, "test-witness"); err != nil {
		t.Errorf("cosignature verification failed: %v", err)
	}
}

// TestAddCheckpointIdempotent verifies that re-submitting the same commit
// (already stored) returns 200 without ancestry.
func TestAddCheckpointIdempotent(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit := strings.Repeat("b", 40)
	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed

	// First submission.
	resp := post(t, baseURL, payload)
	readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first submission: expected 200, got %d", resp.StatusCode)
	}

	// Identical second submission — should still be 200.
	resp2 := post(t, baseURL, payload)
	body2 := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("idempotent submission: expected 200, got %d: %s", resp2.StatusCode, body2)
	}
}

// TestAddCheckpointIdempotentSHA256 is the SHA-256 variant of
// TestAddCheckpointIdempotent.
func TestAddCheckpointIdempotentSHA256(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit := strings.Repeat("b", 64)
	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed

	resp := post(t, baseURL, payload)
	readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first submission: expected 200, got %d", resp.StatusCode)
	}

	resp2 := post(t, baseURL, payload)
	body2 := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("idempotent submission: expected 200, got %d: %s", resp2.StatusCode, body2)
	}
}

// TestAddCheckpointMalformedBody verifies that a request missing the empty-line
// separator returns 400 Bad Request.
func TestAddCheckpointMalformedBody(t *testing.T) {
	baseURL, _, _, stop := setupServer(t)
	defer stop()

	resp := post(t, baseURL, "not-a-valid-payload-at-all")
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointInvalidSignature verifies that a checkpoint signed by an
// unknown key returns 404 (unknown origin).
func TestAddCheckpointInvalidSignature(t *testing.T) {
	baseURL, _, _, stop := setupServer(t)
	defer stop()

	// Sign with a key the server doesn't know about.
	rogue := mustGenerateKey(t, "rogue-origin", note.Ed25519Origin, note.RoleOrigin)
	commit := strings.Repeat("c", 40)
	signed := makeSignedCheckpoint(t, rogue, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown origin, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointMissingAncestry verifies that advancing without an ancestry
// proof returns 422 Unprocessable Entity.
func TestAddCheckpointMissingAncestry(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit1 := strings.Repeat("d", 40)
	signed1 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit1)
	post(t, baseURL, "\n"+signed1) //nolint — first submission, ignore response

	// Try to advance to commit2 without any ancestry proof.
	commit2 := strings.Repeat("e", 40)
	signed2 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit2)
	payload2 := "\n" + signed2 // missing ancestry

	resp := post(t, baseURL, payload2)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for missing ancestry, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointMalformedBase64Ancestry verifies that a corrupted base64
// ancestry line returns 422.
func TestAddCheckpointMalformedBase64Ancestry(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit1 := strings.Repeat("f", 40)
	post(t, baseURL, "\n"+makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit1))

	commit2 := strings.Repeat("9", 40)
	signed2 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commit2)
	payload2 := "!!!not-valid-base64!!!\n\n" + signed2

	resp := post(t, baseURL, payload2)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for malformed base64, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointDisconnectedAncestry verifies that a syntactically valid
// ancestry proof (correctly-hashed commit objects forming a proper chain) is
// rejected with 422 when that chain does not connect back to the witness's
// stored commit for the branch.
func TestAddCheckpointDisconnectedAncestry(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	// Establish an initial checkpoint at a fake commit hash.
	storedCommit := strings.Repeat("1", 40)
	post(t, baseURL, "\n"+makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", storedCommit))

	// Build a two-commit orphan chain that doesn't include storedCommit.
	// orphanA is a root commit (no parent).
	orphanA, orphanAObj := makeTestCommitObject(t, "", "orphan commit A", false)
	// orphanB's parent is orphanA — a valid chain, but wholly disconnected from storedCommit.
	orphanB, orphanBObj := makeTestCommitObject(t, orphanA, "orphan commit B", false)

	ancestryProof := base64.StdEncoding.EncodeToString(orphanAObj) + "\n" +
		base64.StdEncoding.EncodeToString(orphanBObj)

	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", orphanB)
	payload := ancestryProof + "\n\n" + signed

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for disconnected ancestry chain, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointDisconnectedAncestrySHA256 is the SHA-256 variant of
// TestAddCheckpointDisconnectedAncestry.
func TestAddCheckpointDisconnectedAncestrySHA256(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	storedCommit := strings.Repeat("1", 64)
	post(t, baseURL, "\n"+makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", storedCommit))

	orphanA, orphanAObj := makeTestCommitObject(t, "", "orphan commit A", true)
	orphanB, orphanBObj := makeTestCommitObject(t, orphanA, "orphan commit B", true)

	ancestryProof := base64.StdEncoding.EncodeToString(orphanAObj) + "\n" +
		base64.StdEncoding.EncodeToString(orphanBObj)

	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", orphanB)
	payload := ancestryProof + "\n\n" + signed

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for disconnected SHA-256 ancestry chain, got %d: %s", resp.StatusCode, body)
	}
}

// TestAddCheckpointTagImmutability verifies that the witness rejects a second
// checkpoint for an already-pinned tag when the commit hash differs, returning
// 409 Conflict.
func TestAddCheckpointTagImmutability(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit1 := strings.Repeat("a", 40)
	signed1 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/tags/v1.0.0", commit1)
	resp1 := post(t, baseURL, "\n"+signed1)
	readBody(t, resp1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first tag checkpoint: expected 200, got %d", resp1.StatusCode)
	}

	// Attempt to checkpoint the same tag with a different commit.
	commit2 := strings.Repeat("b", 40)
	signed2 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/tags/v1.0.0", commit2)
	resp2 := post(t, baseURL, "\n"+signed2)
	body2 := readBody(t, resp2)

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for moved tag, got %d: %s", resp2.StatusCode, body2)
	}
}

// TestAddCheckpointTagImmutabilitySHA256 is the SHA-256 variant of
// TestAddCheckpointTagImmutability.
func TestAddCheckpointTagImmutabilitySHA256(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	commit1 := strings.Repeat("a", 64)
	signed1 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/tags/v2.0.0", commit1)
	resp1 := post(t, baseURL, "\n"+signed1)
	readBody(t, resp1)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first tag checkpoint: expected 200, got %d", resp1.StatusCode)
	}

	commit2 := strings.Repeat("b", 64)
	signed2 := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/tags/v2.0.0", commit2)
	resp2 := post(t, baseURL, "\n"+signed2)
	body2 := readBody(t, resp2)

	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 for moved tag with SHA-256, got %d: %s", resp2.StatusCode, body2)
	}
}

// makeTestCommitObject builds a minimal, correctly-hashed git commit object
// suitable for use in ancestry proof payloads. parentHash may be empty for a
// root commit. If useSHA256 is true, objects are hashed with SHA-256 (producing
// 64-char hex IDs and using 64-char placeholder tree hashes), matching Git's
// extensions.objectFormat=sha256 mode. Returns the commit ID and the
// wire-format bytes ("commit <size>\n<content>") ready for base64 encoding.
func makeTestCommitObject(t *testing.T, parentHash, message string, useSHA256 bool) (commitID string, wireBytes []byte) {
	t.Helper()

	// Tree hash placeholder — must match the object format length.
	treeHash := strings.Repeat("0", 40)
	if useSHA256 {
		treeHash = strings.Repeat("0", 64)
	}

	var sb strings.Builder
	sb.WriteString("tree " + treeHash + "\n")
	if parentHash != "" {
		sb.WriteString("parent " + parentHash + "\n")
	}
	sb.WriteString("author Test <t@t.com> 1000000000 +0000\n")
	sb.WriteString("committer Test <t@t.com> 1000000000 +0000\n")
	sb.WriteString("\n")
	sb.WriteString(message + "\n")
	content := sb.String()

	if useSHA256 {
		h := sha256.New()
		fmt.Fprintf(h, "commit %d\x00", len(content))
		h.Write([]byte(content))
		commitID = fmt.Sprintf("%x", h.Sum(nil))
	} else {
		h := sha1.New()
		fmt.Fprintf(h, "commit %d\x00", len(content))
		h.Write([]byte(content))
		commitID = fmt.Sprintf("%x", h.Sum(nil))
	}

	wireBytes = []byte(fmt.Sprintf("commit %d\n%s", len(content), content))
	return
}

// TestAddCheckpointValidAncestrySHA256 verifies that a properly-chained
// SHA-256 ancestry proof is accepted by the witness.
func TestAddCheckpointValidAncestrySHA256(t *testing.T) {
	baseURL, originKey, _, stop := setupServer(t)
	defer stop()

	// commitA is a root commit, checkpointed first.
	commitA, commitAObj := makeTestCommitObject(t, "", "root commit", true)
	post(t, baseURL, "\n"+makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commitA))

	// commitB descends from commitA.
	commitB, commitBObj := makeTestCommitObject(t, commitA, "child commit", true)

	ancestryProof := base64.StdEncoding.EncodeToString(commitAObj) + "\n" +
		base64.StdEncoding.EncodeToString(commitBObj)

	signed := makeSignedCheckpoint(t, originKey, "example.com/repo", "refs/heads/main", commitB)
	payload := ancestryProof + "\n\n" + signed

	resp := post(t, baseURL, payload)
	body := readBody(t, resp)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid SHA-256 ancestry, got %d: %s", resp.StatusCode, body)
	}
	if !strings.HasPrefix(body, note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", body)
	}
}

