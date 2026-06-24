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

package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
)

// splitWireFormat splits the add-checkpoint wire format into the ancestry
// section and the signed note. The wire format is:
//
//	<base64-commit-object-1>
//	<base64-commit-object-2>
//	...
//
//	<signed-note>
//
// The first empty line is the separator. Everything before it is ancestry
// lines; everything after is the signed note.
func splitWireFormat(t *testing.T, request string) (ancestry string, signedNote string) {
	t.Helper()
	lines := strings.SplitN(request, "\n", -1)
	for i, line := range lines {
		if line == "" {
			ancestry = strings.Join(lines[:i], "\n")
			signedNote = strings.Join(lines[i+1:], "\n")
			return
		}
	}
	t.Fatalf("no empty line separator found in wire format:\n%s", request)
	return
}

// TestCheckpointRequestBranchBasic verifies that checkpoint-request produces
// valid wire format output for a branch ref.
func TestCheckpointRequestBranchBasic(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "initial commit")

	keyPath := writeKeyFile(t, repoDir, originKey)

	requestFile := filepath.Join(t.TempDir(), "request.txt")
	noteFile := filepath.Join(t.TempDir(), "note.txt")

	out, err := exec.Command(binary,
		"checkpoint-request",
		"--ref", "refs/heads/main",
		"--repo", repoDir,
		"--key", keyPath,
		"--output-request", requestFile,
		"--output-note", noteFile,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint-request failed: %v\n%s", err, out)
	}

	// Verify request file exists and has valid wire format.
	reqBytes, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("reading request file: %v", err)
	}
	request := string(reqBytes)

	// For the first checkpoint there is no prior checkpoint, so no ancestry.
	// The request should start with an empty line (separator) followed by
	// the signed note.
	ancestrySection, signedNote := splitWireFormat(t, request)
	if ancestrySection != "" {
		t.Errorf("expected empty ancestry section for first branch checkpoint, got: %q", ancestrySection)
	}

	// Verify the signed note can be parsed.
	body, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("parsing signed note from request: %v", err)
	}

	expectedBody := originKey.Name + " refs/heads/main\n" + commitHash + "\n"
	if body != expectedBody {
		t.Errorf("unexpected body:\ngot:  %q\nwant: %q", body, expectedBody)
	}

	// Should have exactly one signature (origin only, no witnesses).
	if len(sigLines) != 1 {
		t.Errorf("expected 1 signature line (origin only), got %d: %v", len(sigLines), sigLines)
	}

	// Verify the note file matches the signed note from the request.
	noteBytes, err := os.ReadFile(noteFile)
	if err != nil {
		t.Fatalf("reading note file: %v", err)
	}
	if string(noteBytes) != signedNote {
		t.Errorf("note file does not match signed note in request:\nnote file: %q\nfrom request: %q", string(noteBytes), signedNote)
	}
}

// TestCheckpointRequestTagNoAncestry verifies that tags produce no ancestry
// proof — the output starts with an empty line followed by the signed note.
func TestCheckpointRequestTagNoAncestry(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)

	repoDir := initTestRepo(t)
	commitHash := makeCommit(t, repoDir, "tagged release")
	run(t, repoDir, "git", "tag", "v1.0.0")

	keyPath := writeKeyFile(t, repoDir, originKey)

	requestFile := filepath.Join(t.TempDir(), "request.txt")
	noteFile := filepath.Join(t.TempDir(), "note.txt")

	out, err := exec.Command(binary,
		"checkpoint-request",
		"--ref", "refs/tags/v1.0.0",
		"--repo", repoDir,
		"--key", keyPath,
		"--output-request", requestFile,
		"--output-note", noteFile,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint-request failed: %v\n%s", err, out)
	}

	reqBytes, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("reading request file: %v", err)
	}
	request := string(reqBytes)

	// For tags, there is no ancestry proof.
	ancestrySection, signedNote := splitWireFormat(t, request)
	if ancestrySection != "" {
		t.Errorf("expected empty ancestry section for tag, got: %q", ancestrySection)
	}

	// Verify the signed note body contains the tag ref and commit.
	body, _, err := note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("parsing signed note: %v", err)
	}

	expectedBody := originKey.Name + " refs/tags/v1.0.0\n" + commitHash + "\n"
	if body != expectedBody {
		t.Errorf("unexpected body:\ngot:  %q\nwant: %q", body, expectedBody)
	}
}

// TestCheckpointRequestMissingFlags verifies that missing required flags
// produce a usage error.
func TestCheckpointRequestMissingFlags(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "initial commit")

	keyPath := writeKeyFile(t, repoDir, originKey)

	tmpDir := t.TempDir()
	reqFile := filepath.Join(tmpDir, "req.txt")
	noteFile := filepath.Join(tmpDir, "note.txt")

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing --ref",
			args: []string{"checkpoint-request", "--key", keyPath, "--repo", repoDir, "--output-request", reqFile, "--output-note", noteFile},
		},
		{
			name: "missing --output-request",
			args: []string{"checkpoint-request", "--ref", "refs/heads/main", "--key", keyPath, "--repo", repoDir, "--output-note", noteFile},
		},
		{
			name: "missing --output-note",
			args: []string{"checkpoint-request", "--ref", "refs/heads/main", "--key", keyPath, "--repo", repoDir, "--output-request", reqFile},
		},
		{
			name: "missing --key and --kms-key",
			args: []string{"checkpoint-request", "--ref", "refs/heads/main", "--repo", repoDir, "--output-request", reqFile, "--output-note", noteFile},
		},
		{
			name: "both --key and --kms-key",
			args: []string{"checkpoint-request", "--ref", "refs/heads/main", "--key", keyPath, "--kms-key", "projects/x/locations/y/keyRings/z/cryptoKeys/k/cryptoKeyVersions/1", "--repo", repoDir, "--output-request", reqFile, "--output-note", noteFile},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(binary, tc.args...).CombinedOutput()
			if err == nil {
				t.Fatalf("expected checkpoint-request to fail with %s, but it succeeded:\n%s", tc.name, out)
			}
			// Verify it is a usage error (contains "error:").
			if !strings.Contains(string(out), "error:") {
				t.Errorf("expected error message in output for %s, got:\n%s", tc.name, out)
			}
		})
	}
}

// TestCheckpointRequestWithAncestry verifies that a second checkpoint-request
// for a branch includes ancestry proof lines.
func TestCheckpointRequestWithAncestry(t *testing.T) {
	binary := mustFindBinary(t)

	originKey := mustGenerateKey(t, "test-origin", note.Ed25519Origin, note.RoleOrigin)
	witnessKey := mustGenerateKey(t, "test-witness", note.Ed25519Cosigner, note.RoleCosigner)
	ws := newFakeWitness(t, witnessKey, originKey)
	defer ws.Close()

	repoDir := initTestRepo(t)
	_ = makeCommit(t, repoDir, "first commit")

	keyPath := writeKeyFile(t, repoDir, originKey)
	policyPath := writePolicyFile(t, repoDir, originKey, witnessKey, ws.URL)

	// First, do a full checkpoint so a checkpoint ref exists.
	out, err := exec.Command(binary,
		"checkpoint",
		"--ref", "refs/heads/main",
		"--repo", repoDir,
		"--key", keyPath,
		"--policy", policyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("first checkpoint failed: %v\n%s", err, out)
	}

	// Make a second commit.
	_ = makeCommit(t, repoDir, "second commit")

	// Now run checkpoint-request — it should include ancestry proof.
	requestFile := filepath.Join(t.TempDir(), "request.txt")
	noteFile := filepath.Join(t.TempDir(), "note.txt")
	out, err = exec.Command(binary,
		"checkpoint-request",
		"--ref", "refs/heads/main",
		"--repo", repoDir,
		"--key", keyPath,
		"--output-request", requestFile,
		"--output-note", noteFile,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint-request failed: %v\n%s", err, out)
	}

	reqBytes, err := os.ReadFile(requestFile)
	if err != nil {
		t.Fatalf("reading request file: %v", err)
	}
	request := string(reqBytes)

	// Split into ancestry and note sections.
	ancestrySection, signedNote := splitWireFormat(t, request)

	if ancestrySection == "" {
		t.Error("expected non-empty ancestry section for second branch checkpoint")
	}

	// Each line in ancestry section should be non-empty (base64-encoded).
	ancestryLines := strings.Split(ancestrySection, "\n")
	for i, line := range ancestryLines {
		if line == "" {
			t.Errorf("empty ancestry line at index %d", i)
		}
	}

	// Verify the signed note can be parsed.
	_, _, err = note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("parsing signed note from request: %v", err)
	}
}
