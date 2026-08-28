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

	base := []string{"checkpoint-request", "--mode", "tlog", "--repo", repoDir}
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "missing --output-request",
			args: append(base, "--key", keyPath, "--output-note", noteFile),
		},
		{
			name: "missing --output-note",
			args: append(base, "--key", keyPath, "--output-request", reqFile),
		},
		{
			name: "missing --key and --kms-key",
			args: append(base, "--output-request", reqFile, "--output-note", noteFile),
		},
		{
			name: "both --key and --kms-key",
			args: append(base, "--key", keyPath, "--kms-key", "projects/x/locations/y/keyRings/z/cryptoKeys/k/cryptoKeyVersions/1", "--output-request", reqFile, "--output-note", noteFile),
		},
		{
			// A tlog checkpoint covers the whole log, so a ref means the
			// caller expects something this command will not do.
			name: "--ref in tlog mode",
			args: append(base, "--ref", "refs/heads/main", "--key", keyPath, "--output-request", reqFile, "--output-note", noteFile),
		},
		{
			// git-checkpoint witnesses are reached over HTTP, so there is
			// nothing to decompose.
			name: "git-checkpoint mode",
			args: []string{"checkpoint-request", "--repo", repoDir, "--ref", "refs/heads/main", "--key", keyPath, "--output-request", reqFile, "--output-note", noteFile},
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
