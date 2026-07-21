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
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
)

func mustFindBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GENWITNESSKEY_BIN"); p != "" {
		return p
	}
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "tools", "genwitnesskey", "genwitnesskey_", "genwitnesskey"),
				filepath.Join(srcDir, ws, "tools", "genwitnesskey", "genwitnesskey"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("genwitnesskey binary not found; run with: bazel test //tools/genwitnesskey:genwitnesskey_test")
	return ""
}

func TestGenWitnessKey(t *testing.T) {
	binary := mustFindBinary(t)
	dir := t.TempDir()

	cmd := exec.Command(binary, "--output-dir", dir, "--name", "test-witness")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("genwitnesskey failed: %v\nOutput: %s", err, out)
	}

	keyPath := filepath.Join(dir, "witness-key")

	// Check file permissions are 0600.
	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat(%s): %v", keyPath, err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected permissions 0600, got %04o", perm)
	}

	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", keyPath, err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key file, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	// Verify vkey format: name+hexhash+base64data
	if !regexp.MustCompile(`^test-witness\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}

	// Extract and check the base64 data portion.
	parts := strings.SplitN(vkey, "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}

	// Should be 33 bytes: 1 type byte + 32 pubkey bytes.
	if len(data) != 33 {
		t.Fatalf("expected 33 bytes of vkey data, got %d", len(data))
	}

	// Type byte should be 0x04 (Ed25519 cosigner).
	if data[0] != 0x04 {
		t.Fatalf("expected type byte 0x04, got 0x%02x", data[0])
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		t.Fatalf("decoding seed base64: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	// Read back with note.ReadKeyFile and verify round-trip.
	readSigner, err := note.ReadKeyFile(keyPath, note.RoleCosigner)
	if err != nil {
		t.Fatalf("ReadKeyFile: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

	// Signature round trip: generate a dummy origin key, sign a checkpoint note,
	// then cosign it using the witness signer loaded from the generated witness key.
	originSigner, err := note.GenerateKey("test-origin", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatalf("GenerateKey origin: %v", err)
	}

	testBody := "test-origin refs/heads/main\n0123456789abcdef0123456789abcdef01234567\n"
	signedNote, err := note.Sign(testBody, originSigner)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}

	cosigLine, err := note.Cosign(signedNote, readSigner)
	if err != nil {
		t.Fatalf("note.Cosign: %v", err)
	}

	pubName, sigType, pubKey, err := note.ParseVKey(vkey)
	if err != nil {
		t.Fatalf("note.ParseVKey: %v", err)
	}
	if pubName != "test-witness" {
		t.Fatalf("expected pubName test-witness, got %s", pubName)
	}

	body, err := note.ExtractBody(signedNote)
	if err != nil {
		t.Fatalf("note.ExtractBody: %v", err)
	}

	if err := note.VerifyCosignature(body, cosigLine, pubKey, sigType, pubName); err != nil {
		t.Fatalf("cosignature verification failed: %v", err)
	}
}
