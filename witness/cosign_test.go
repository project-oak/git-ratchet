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

// Package main tests the witness-cosign CLI by invoking the compiled binary
// with crafted request files and checking exit codes and stdout/stderr output.
package main_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
)

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

func makeSignedCheckpoint(t *testing.T, signer *note.Signer, origin, ref, commit string) string {
	t.Helper()
	body := origin + " " + ref + "\n" + commit + "\n"
	signed, err := note.Sign(body, signer)
	if err != nil {
		t.Fatalf("signing checkpoint: %v", err)
	}
	return signed
}

func makeTestCommitObject(t *testing.T, parentHash, message string, useSHA256 bool) (commitID string, wireBytes []byte) {
	t.Helper()
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

// mustFindCosignBinary locates the compiled cosign binary from Bazel runfiles.
func mustFindCosignBinary(t *testing.T) string {
	t.Helper()
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "witness", "cosign_", "cosign"),
				filepath.Join(srcDir, ws, "witness", "cosign"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("cosign binary not found; run with: bazel test //witness:cosign_test")
	return ""
}

// cosignSetup creates test keys, writes them to temp files, and returns paths
// needed to invoke the cosign binary.
type cosignSetup struct {
	binary      string
	keyPath     string
	originsPath string
	originKey   *note.Signer
	witnessKey  *note.Signer
	tmpDir      string
}

func setupCosign(t *testing.T) *cosignSetup {
	t.Helper()
	bin := mustFindCosignBinary(t)
	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)
	witnessKey := mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner)

	tmpDir := t.TempDir()

	witnessKeyPath := filepath.Join(tmpDir, "witness.key")
	mustWriteKey(t, witnessKeyPath, witnessKey)

	originsPath := filepath.Join(tmpDir, "origins.txt")
	if err := os.WriteFile(originsPath, []byte(originKey.VKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	return &cosignSetup{
		binary:      bin,
		keyPath:     witnessKeyPath,
		originsPath: originsPath,
		originKey:   originKey,
		witnessKey:  witnessKey,
		tmpDir:      tmpDir,
	}
}

// runCosign invokes the cosign binary with the given args and returns stdout,
// stderr, and any error.
func runCosign(t *testing.T, s *cosignSetup, requestPath string, extraArgs ...string) (stdout, stderr string, err error) {
	t.Helper()
	args := []string{
		"--request", requestPath,
		"--origin-vkeys", s.originsPath,
		"--key", s.keyPath,
	}
	args = append(args, extraArgs...)
	cmd := exec.Command(s.binary, args...)
	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err = cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// writeRequest writes an add-checkpoint request body to a temp file and returns its path.
func writeRequest(t *testing.T, dir, payload string) string {
	t.Helper()
	path := filepath.Join(dir, "request.txt")
	if err := os.WriteFile(path, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCosignFirstCheckpoint verifies that the cosign binary accepts a first
// checkpoint (no stored state) and produces a valid cosignature.
func TestCosignFirstCheckpoint(t *testing.T) {
	s := setupCosign(t)
	commit := strings.Repeat("a", 40)
	signed := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commit)
	payload := "\n" + signed // empty ancestry + separator

	reqPath := writeRequest(t, s.tmpDir, payload)
	stdout, stderr, err := runCosign(t, s, reqPath)
	if err != nil {
		t.Fatalf("cosign failed: %v\nstderr: %s", err, stderr)
	}

	cosigLine := strings.TrimSpace(stdout)
	if !strings.HasPrefix(cosigLine, note.SigPrefix) {
		t.Errorf("expected cosignature line starting with %q, got: %q", note.SigPrefix, cosigLine)
	}

	// Verify the cosignature is cryptographically valid.
	_, _, witnessPub, err := note.ParseVKey(s.witnessKey.VKey())
	if err != nil {
		t.Fatalf("parsing witness vkey: %v", err)
	}
	noteBody := "example.com/repo refs/heads/main\n" + commit + "\n"
	if err := note.VerifyCosignature(noteBody, cosigLine, witnessPub, note.Ed25519Cosigner, "test-witness"); err != nil {
		t.Errorf("cosignature verification failed: %v", err)
	}
}

// TestCosignFirstCheckpointTag verifies that a first tag checkpoint works.
func TestCosignFirstCheckpointTag(t *testing.T) {
	s := setupCosign(t)
	commit := strings.Repeat("b", 40)
	signed := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/tags/v1.0.0", commit)
	payload := "\n" + signed

	reqPath := writeRequest(t, s.tmpDir, payload)
	stdout, stderr, err := runCosign(t, s, reqPath)
	if err != nil {
		t.Fatalf("cosign failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", stdout)
	}
}

// TestCosignIdempotent verifies that re-submitting the same commit with a
// matching stored checkpoint succeeds (no ancestry needed).
func TestCosignIdempotent(t *testing.T) {
	s := setupCosign(t)
	commit := strings.Repeat("c", 40)
	signed := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commit)

	// Create a stored checkpoint file with the same commit.
	storedPath := filepath.Join(s.tmpDir, "stored.txt")
	// The stored checkpoint is the signed note + a cosignature.
	reqPath := writeRequest(t, s.tmpDir, "\n"+signed)
	stdout1, _, err := runCosign(t, s, reqPath)
	if err != nil {
		t.Fatalf("first cosign failed: %v", err)
	}

	// Write the full cosigned checkpoint as the stored state.
	cosigned := note.AppendSignature(signed, strings.TrimSpace(stdout1))
	if err := os.WriteFile(storedPath, []byte(cosigned), 0644); err != nil {
		t.Fatal(err)
	}

	// Re-submit the same commit with the stored checkpoint.
	stdout2, stderr2, err := runCosign(t, s, reqPath, "--stored-checkpoint", storedPath)
	if err != nil {
		t.Fatalf("idempotent cosign failed: %v\nstderr: %s", err, stderr2)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout2), note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", stdout2)
	}
}

// TestCosignTagImmutability verifies that advancing a tag to a different commit
// is rejected when a stored checkpoint pins it.
func TestCosignTagImmutability(t *testing.T) {
	s := setupCosign(t)
	commit1 := strings.Repeat("d", 40)
	signed1 := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/tags/v1.0.0", commit1)

	// Cosign the first tag checkpoint and save it as stored state.
	reqPath1 := writeRequest(t, s.tmpDir, "\n"+signed1)
	stdout1, _, err := runCosign(t, s, reqPath1)
	if err != nil {
		t.Fatalf("first cosign failed: %v", err)
	}
	storedPath := filepath.Join(s.tmpDir, "stored-tag.txt")
	cosigned := note.AppendSignature(signed1, strings.TrimSpace(stdout1))
	if err := os.WriteFile(storedPath, []byte(cosigned), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to advance the tag to a different commit — should fail.
	commit2 := strings.Repeat("e", 40)
	signed2 := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/tags/v1.0.0", commit2)
	reqPath2 := filepath.Join(s.tmpDir, "request2.txt")
	if err := os.WriteFile(reqPath2, []byte("\n"+signed2), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := runCosign(t, s, reqPath2, "--stored-checkpoint", storedPath)
	if err == nil {
		t.Fatal("expected cosign to fail for moved tag, but it succeeded")
	}
	if !strings.Contains(stderr, "tags are immutable") {
		t.Errorf("expected immutability error, got stderr: %s", stderr)
	}
}

// TestCosignMissingAncestry verifies that advancing a branch without an
// ancestry proof is rejected when a stored checkpoint exists.
func TestCosignMissingAncestry(t *testing.T) {
	s := setupCosign(t)
	commit1 := strings.Repeat("f", 40)
	signed1 := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commit1)

	// Cosign the first checkpoint and save as stored state.
	reqPath1 := writeRequest(t, s.tmpDir, "\n"+signed1)
	stdout1, _, err := runCosign(t, s, reqPath1)
	if err != nil {
		t.Fatalf("first cosign failed: %v", err)
	}
	storedPath := filepath.Join(s.tmpDir, "stored-branch.txt")
	cosigned := note.AppendSignature(signed1, strings.TrimSpace(stdout1))
	if err := os.WriteFile(storedPath, []byte(cosigned), 0644); err != nil {
		t.Fatal(err)
	}

	// Try to advance to a new commit without ancestry — should fail.
	commit2 := strings.Repeat("9", 40)
	signed2 := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commit2)
	reqPath2 := filepath.Join(s.tmpDir, "request2.txt")
	if err := os.WriteFile(reqPath2, []byte("\n"+signed2), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := runCosign(t, s, reqPath2, "--stored-checkpoint", storedPath)
	if err == nil {
		t.Fatal("expected cosign to fail for missing ancestry, but it succeeded")
	}
	if !strings.Contains(stderr, "ancestry verification failed") {
		t.Errorf("expected ancestry error, got stderr: %s", stderr)
	}
}

// TestCosignValidAncestry verifies that a properly-chained ancestry proof is
// accepted when advancing a branch.
func TestCosignValidAncestry(t *testing.T) {
	s := setupCosign(t)

	// commitA is the initial checkpoint.
	commitA, commitAObj := makeTestCommitObject(t, "", "root commit", false)
	signedA := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commitA)

	reqPathA := writeRequest(t, s.tmpDir, "\n"+signedA)
	stdoutA, _, err := runCosign(t, s, reqPathA)
	if err != nil {
		t.Fatalf("first cosign failed: %v", err)
	}
	storedPath := filepath.Join(s.tmpDir, "stored-ancestry.txt")
	cosigned := note.AppendSignature(signedA, strings.TrimSpace(stdoutA))
	if err := os.WriteFile(storedPath, []byte(cosigned), 0644); err != nil {
		t.Fatal(err)
	}

	// commitB descends from commitA.
	commitB, commitBObj := makeTestCommitObject(t, commitA, "child commit", false)
	ancestryProof := base64.StdEncoding.EncodeToString(commitAObj) + "\n" +
		base64.StdEncoding.EncodeToString(commitBObj)
	signedB := makeSignedCheckpoint(t, s.originKey, "example.com/repo", "refs/heads/main", commitB)
	payload := ancestryProof + "\n\n" + signedB

	reqPathB := filepath.Join(s.tmpDir, "request-advance.txt")
	if err := os.WriteFile(reqPathB, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := runCosign(t, s, reqPathB, "--stored-checkpoint", storedPath)
	if err != nil {
		t.Fatalf("cosign with ancestry failed: %v\nstderr: %s", err, stderr)
	}
	if !strings.HasPrefix(strings.TrimSpace(stdout), note.SigPrefix) {
		t.Errorf("expected cosignature line, got: %q", stdout)
	}
}

// TestCosignUnknownOrigin verifies that a checkpoint signed by an unknown
// origin key is rejected.
func TestCosignUnknownOrigin(t *testing.T) {
	s := setupCosign(t)
	rogue := mustGenerateKey(t, "rogue-origin", note.Ed25519Origin, note.RoleOrigin)
	commit := strings.Repeat("a", 40)
	signed := makeSignedCheckpoint(t, rogue, "example.com/repo", "refs/heads/main", commit)

	reqPath := writeRequest(t, s.tmpDir, "\n"+signed)
	_, stderr, err := runCosign(t, s, reqPath)
	if err == nil {
		t.Fatal("expected cosign to fail for unknown origin, but it succeeded")
	}
	if !strings.Contains(stderr, "unknown origin") {
		t.Errorf("expected unknown origin error, got stderr: %s", stderr)
	}
}

// TestCosignMissingFlags verifies that missing required flags produce errors.
func TestCosignMissingFlags(t *testing.T) {
	s := setupCosign(t)
	reqPath := writeRequest(t, s.tmpDir, "dummy")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing --request",
			args: []string{"--origin-vkeys", s.originsPath, "--key", s.keyPath},
			want: "--request is required",
		},
		{
			name: "missing --origin-vkeys",
			args: []string{"--request", reqPath, "--key", s.keyPath},
			want: "--origin-vkeys is required",
		},
		{
			name: "missing --key",
			args: []string{"--request", reqPath, "--origin-vkeys", s.originsPath},
			want: "--key is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(s.binary, tt.args...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("expected non-zero exit, but command succeeded")
			}
			if !strings.Contains(string(out), tt.want) {
				t.Errorf("expected error containing %q, got: %s", tt.want, out)
			}
		})
	}
}

// TestCosignMalformedRequest verifies that a malformed request file is rejected.
func TestCosignMalformedRequest(t *testing.T) {
	s := setupCosign(t)
	reqPath := writeRequest(t, s.tmpDir, "no-separator-here")

	_, stderr, err := runCosign(t, s, reqPath)
	if err == nil {
		t.Fatal("expected cosign to fail for malformed request, but it succeeded")
	}
	if !strings.Contains(stderr, "missing empty line separator") {
		t.Errorf("expected separator error, got stderr: %s", stderr)
	}
}
