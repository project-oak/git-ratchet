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

// Package main tests the cosign CLI by invoking the compiled binary
// with crafted request files and checking exit codes and stdout/stderr output.
package main_test

import (
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
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(skey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// mustFindCosignBinary locates the compiled cosign binary from Bazel runfiles.
func mustFindCosignBinary(t *testing.T) string {
	t.Helper()
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "cosign", "cosign_", "cosign"),
				filepath.Join(srcDir, ws, "cosign", "cosign"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("cosign binary not found; run with: bazel test //cosign:cosign_test")
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
		{
			// A witness with no stored state cannot ratchet, so unlike an
			// HTTP witness's optional state file this one is required.
			name: "missing --stored-checkpoint",
			args: []string{"--request", reqPath, "--origin-vkeys", s.originsPath, "--key", s.keyPath},
			want: "--stored-checkpoint is required",
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
