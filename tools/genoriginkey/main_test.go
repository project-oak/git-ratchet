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
	if p := os.Getenv("GENORIGINKEY_BIN"); p != "" {
		return p
	}
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "tools", "genoriginkey", "genoriginkey_", "genoriginkey"),
				filepath.Join(srcDir, ws, "tools", "genoriginkey", "genoriginkey"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("genoriginkey binary not found; run with: bazel test //tools/genoriginkey:genoriginkey_test")
	return ""
}

func TestGenOriginKey(t *testing.T) {
	binary := mustFindBinary(t)

	cmd := exec.Command(binary, "--name", "test-origin")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genoriginkey failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key output, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	// Verify vkey format: name+hexhash+base64data
	if !regexp.MustCompile(`^test-origin\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
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

	// Type byte should be 0x01 (Ed25519 origin).
	if data[0] != 0x01 {
		t.Fatalf("expected type byte 0x01, got 0x%02x", data[0])
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		t.Fatalf("decoding seed base64: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	// Read back with note.ReadKeyData and verify round-trip.
	readSigner, err := note.ReadKeyData(out, note.RoleOrigin)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

	// Signature round trip: sign a test note using the read signer (loaded from seed)
	// and verify the signature using the vkey.
	testBody := "test-origin refs/heads/main\n0123456789abcdef0123456789abcdef01234567\n"
	signedNote, err := note.Sign(testBody, readSigner)
	if err != nil {
		t.Fatalf("note.Sign: %v", err)
	}

	body, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		t.Fatalf("note.ParseSignedNote: %v", err)
	}

	pubName, sigType, pubKey, err := note.ParseVKey(vkey)
	if err != nil {
		t.Fatalf("note.ParseVKey: %v", err)
	}
	if pubName != "test-origin" {
		t.Fatalf("expected pubName test-origin, got %s", pubName)
	}

	if len(sigLines) != 1 {
		t.Fatalf("expected 1 signature line, got %d", len(sigLines))
	}

	if err := note.VerifySignature(body, sigLines[0], pubKey, sigType); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}
