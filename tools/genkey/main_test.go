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
	if p := os.Getenv("GENKEY_BIN"); p != "" {
		return p
	}
	if srcDir := os.Getenv("TEST_SRCDIR"); srcDir != "" {
		for _, ws := range []string{"_main", "__main__"} {
			paths := []string{
				filepath.Join(srcDir, ws, "tools", "genkey", "genkey_", "genkey"),
				filepath.Join(srcDir, ws, "tools", "genkey", "genkey"),
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					return p
				}
			}
		}
	}
	t.Fatal("genkey binary not found; run with: bazel test //tools/genkey:genkey_test")
	return ""
}

func TestGenKey_Origin_Ed25519(t *testing.T) {
	binary := mustFindBinary(t)

	cmd := exec.Command(binary, "--role", "origin", "--algo", "ed25519", "--name", "test-origin")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key output, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	if !regexp.MustCompile(`^test-origin\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}

	parts := strings.SplitN(vkey, "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}

	// 1 byte type + 32 bytes Ed25519 pubkey
	if len(data) != 33 {
		t.Fatalf("expected 33 bytes of vkey data, got %d", len(data))
	}
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

	readSigner, err := note.ReadKeyData(out, note.RoleOrigin)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

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

func TestGenKey_Origin_MLDSA(t *testing.T) {
	binary := mustFindBinary(t)

	cmd := exec.Command(binary, "--role", "origin", "--algo", "mldsa44", "--name", "test-origin-pq")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key output, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	if !regexp.MustCompile(`^test-origin-pq\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}

	parts := strings.SplitN(vkey, "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}

	// 1 byte type (0x06) + 1312 bytes ML-DSA-44 pubkey
	if len(data) != 1313 {
		t.Fatalf("expected 1313 bytes of vkey data, got %d", len(data))
	}
	if data[0] != 0x06 {
		t.Fatalf("expected type byte 0x06, got 0x%02x", data[0])
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		t.Fatalf("decoding seed base64: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleOrigin)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

	testBody := "test-origin-pq refs/heads/main\n0123456789abcdef0123456789abcdef01234567\n"
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
	if pubName != "test-origin-pq" {
		t.Fatalf("expected pubName test-origin-pq, got %s", pubName)
	}

	if len(sigLines) != 1 {
		t.Fatalf("expected 1 signature line, got %d", len(sigLines))
	}

	if err := note.VerifySignature(body, sigLines[0], pubKey, sigType); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestGenKey_Witness_Ed25519(t *testing.T) {
	binary := mustFindBinary(t)

	cmd := exec.Command(binary, "--role", "witness", "--algo", "ed25519", "--name", "test-witness")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key output, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	if !regexp.MustCompile(`^test-witness\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}

	parts := strings.SplitN(vkey, "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}

	if len(data) != 33 {
		t.Fatalf("expected 33 bytes of vkey data, got %d", len(data))
	}
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

	readSigner, err := note.ReadKeyData(out, note.RoleCosigner)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

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

func TestGenKey_Witness_MLDSA(t *testing.T) {
	binary := mustFindBinary(t)

	cmd := exec.Command(binary, "--role", "witness", "--algo", "mldsa44", "--name", "test-witness-pq")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("genkey failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines in key output, got %d", len(lines))
	}

	vkey := lines[0]
	seedB64 := lines[1]

	if !regexp.MustCompile(`^test-witness-pq\+[0-9a-f]{8}\+.+$`).MatchString(vkey) {
		t.Fatalf("vkey format invalid: %s", vkey)
	}

	parts := strings.SplitN(vkey, "+", 3)
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding vkey data: %v", err)
	}

	if len(data) != 1313 {
		t.Fatalf("expected 1313 bytes of vkey data, got %d", len(data))
	}
	if data[0] != 0x06 {
		t.Fatalf("expected type byte 0x06, got 0x%02x", data[0])
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		t.Fatalf("decoding seed base64: %v", err)
	}
	if len(seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(seed))
	}

	readSigner, err := note.ReadKeyData(out, note.RoleCosigner)
	if err != nil {
		t.Fatalf("ReadKeyData: %v", err)
	}
	if readSigner.VKey() != vkey {
		t.Fatalf("round-trip vkey mismatch: got %s, want %s", readSigner.VKey(), vkey)
	}

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
	if pubName != "test-witness-pq" {
		t.Fatalf("expected pubName test-witness-pq, got %s", pubName)
	}

	body, err := note.ExtractBody(signedNote)
	if err != nil {
		t.Fatalf("note.ExtractBody: %v", err)
	}

	if err := note.VerifyCosignature(body, cosigLine, pubKey, sigType, pubName); err != nil {
		t.Fatalf("cosignature verification failed: %v", err)
	}
}

func TestGenKey_InvalidFlags(t *testing.T) {
	binary := mustFindBinary(t)

	// Invalid role
	cmdRole := exec.Command(binary, "--role", "invalid")
	if err := cmdRole.Run(); err == nil {
		t.Errorf("expected error for invalid role, got success")
	}

	// Invalid algo
	cmdAlgo := exec.Command(binary, "--algo", "invalid")
	if err := cmdAlgo.Run(); err == nil {
		t.Errorf("expected error for invalid algo, got success")
	}
}
