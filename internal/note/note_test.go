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

package note

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/mldsa"
)

// writeKeyFile is a test helper that writes a signer's key to a file
// in vkey + seed format.
func writeKeyFile(t *testing.T, path string, s *Signer) {
	t.Helper()
	if s.seed == nil {
		t.Fatal("cannot write key file for KMS-backed signer (no local seed)")
	}
	content := s.VKey() + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	s, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"
	signed, err := Sign(body, s)
	if err != nil {
		t.Fatal(err)
	}

	_, sigLines, err := ParseSignedNote(signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigLines) != 1 {
		t.Fatalf("expected 1 sig line, got %d", len(sigLines))
	}

	if err := VerifySignature(body, sigLines[0], s.pub, Ed25519Origin); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestMLDSA44SignVerify(t *testing.T) {
	s, err := GenerateKey("test-origin-pq", MLDSA44, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"
	signed, err := Sign(body, s)
	if err != nil {
		t.Fatal(err)
	}

	_, sigLines, err := ParseSignedNote(signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigLines) != 1 {
		t.Fatalf("expected 1 sig line, got %d", len(sigLines))
	}

	if err := VerifySignature(body, sigLines[0], s.pub, MLDSA44); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestEd25519CosignVerify(t *testing.T) {
	origin, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := GenerateKey("test-witness", Ed25519Cosigner, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"
	signed, err := Sign(body, origin)
	if err != nil {
		t.Fatal(err)
	}

	cosigLine, err := Cosign(signed, witness)
	if err != nil {
		t.Fatal(err)
	}

	noteBody, err := ExtractBody(signed)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCosignature(noteBody, cosigLine, witness.pub, Ed25519Cosigner, witness.Name); err != nil {
		t.Fatalf("cosig verify failed: %v", err)
	}
}

func TestMLDSA44CosignVerify(t *testing.T) {
	origin, err := GenerateKey("test-origin-pq", MLDSA44, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := GenerateKey("test-witness-pq", MLDSA44, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"
	signed, err := Sign(body, origin)
	if err != nil {
		t.Fatal(err)
	}

	cosigLine, err := Cosign(signed, witness)
	if err != nil {
		t.Fatal(err)
	}

	noteBody, err := ExtractBody(signed)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyCosignature(noteBody, cosigLine, witness.pub, MLDSA44, witness.Name); err != nil {
		t.Fatalf("cosig verify failed: %v", err)
	}
}

func TestMLDSA44VKeyRoundTrip(t *testing.T) {
	s, err := GenerateKey("example.com/witness-pq", MLDSA44, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	vkey := s.VKey()
	name, sigType, pub, err := ParseVKey(vkey)
	if err != nil {
		t.Fatal(err)
	}

	if name != "example.com/witness-pq" {
		t.Errorf("name: got %q, want %q", name, "example.com/witness-pq")
	}
	if sigType != MLDSA44 {
		t.Errorf("sigType: got 0x%02x, want 0x%02x", sigType, MLDSA44)
	}

	mlPub, ok := pub.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("expected *mldsa.PublicKey, got %T", pub)
	}

	originalPub := s.pub.(*mldsa.PublicKey)
	if !mlPub.Equal(originalPub) {
		t.Error("public key mismatch after round-trip")
	}

	// Reformat and check it matches.
	vkey2 := FormatVKey(name, pub, sigType)
	if vkey != vkey2 {
		t.Errorf("vkey round-trip failed:\n  got:  %s\n  want: %s", vkey2, vkey)
	}
}

func TestEd25519VKeyRoundTrip(t *testing.T) {
	s, err := GenerateKey("example.com/log", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}

	vkey := s.VKey()
	name, sigType, pub, err := ParseVKey(vkey)
	if err != nil {
		t.Fatal(err)
	}

	if name != "example.com/log" {
		t.Errorf("name: got %q, want %q", name, "example.com/log")
	}
	if sigType != Ed25519Origin {
		t.Errorf("sigType: got 0x%02x, want 0x%02x", sigType, Ed25519Origin)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("expected ed25519.PublicKey, got %T", pub)
	}

	originalPub := s.pub.(ed25519.PublicKey)
	if !edPub.Equal(originalPub) {
		t.Error("public key mismatch after round-trip")
	}
}

func TestKeyFileRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sigType SigType
		role    KeyRole
	}{
		{"ed25519-origin", Ed25519Origin, RoleOrigin},
		{"ed25519-cosigner", Ed25519Cosigner, RoleCosigner},
		{"mldsa44-origin", MLDSA44, RoleOrigin},
		{"mldsa44-cosigner", MLDSA44, RoleCosigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := GenerateKey("test.example/"+tc.name, tc.sigType, tc.role)
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "key")
			writeKeyFile(t, path, s)

			// Read back.
			s2, err := ReadKeyFile(path, tc.role)
			if err != nil {
				t.Fatal(err)
			}

			if s.Name != s2.Name {
				t.Errorf("name: got %q, want %q", s2.Name, s.Name)
			}
			if s.VKey() != s2.VKey() {
				t.Errorf("vkey mismatch:\n  got:  %s\n  want: %s", s2.VKey(), s.VKey())
			}
			if base64.StdEncoding.EncodeToString(s.Seed()) != base64.StdEncoding.EncodeToString(s2.Seed()) {
				t.Error("seed mismatch")
			}
		})
	}
}

func TestCrossAlgorithmRejection(t *testing.T) {
	ed, err := GenerateKey("test-ed", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	ml, err := GenerateKey("test-ml", MLDSA44, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"

	// Sign with Ed25519, try to verify with ML-DSA-44 key.
	signed, _ := Sign(body, ed)
	_, sigs, _ := ParseSignedNote(signed)
	if err := VerifySignature(body, sigs[0], ml.pub, MLDSA44); err == nil {
		t.Error("expected cross-algorithm verification to fail (Ed25519 sig, ML-DSA key)")
	}

	// Sign with ML-DSA-44, try to verify with Ed25519 key.
	signed2, _ := Sign(body, ml)
	_, sigs2, _ := ParseSignedNote(signed2)
	if err := VerifySignature(body, sigs2[0], ed.pub, Ed25519Origin); err == nil {
		t.Error("expected cross-algorithm verification to fail (ML-DSA sig, Ed25519 key)")
	}
}

func TestNewSignerFromSeed(t *testing.T) {
	// Generate, extract seed, reconstruct, verify same vkey.
	for _, tc := range []struct {
		name    string
		sigType SigType
		role    KeyRole
	}{
		{"ed25519", Ed25519Origin, RoleOrigin},
		{"mldsa44", MLDSA44, RoleOrigin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s1, err := GenerateKey("test.example/"+tc.name, tc.sigType, tc.role)
			if err != nil {
				t.Fatal(err)
			}

			s2, err := NewSigner("test.example/"+tc.name, s1.Seed(), tc.sigType, tc.role)
			if err != nil {
				t.Fatal(err)
			}

			if s1.VKey() != s2.VKey() {
				t.Errorf("vkey mismatch from seed:\n  got:  %s\n  want: %s", s2.VKey(), s1.VKey())
			}
		})
	}
}

func TestSignRequiresOriginRole(t *testing.T) {
	cosigner, err := GenerateKey("test-cosigner", Ed25519Cosigner, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign("body\n", cosigner); err == nil {
		t.Error("expected Sign to reject cosigner role")
	}
}

func TestCosignRequiresCosignerRole(t *testing.T) {
	origin, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := Sign("body\n", origin)
	if _, err := Cosign(signed, origin); err == nil {
		t.Error("expected Cosign to reject origin role")
	}
}

func TestMLDSA44CosignedMessageFormat(t *testing.T) {
	// Verify the binary message structure has the right label and fields.
	msg, err := buildCosignedMessage("my-witness", 1234567890, "example.com refs/heads/main\nabc123\n")
	if err != nil {
		t.Fatal(err)
	}

	// Check label.
	expectedLabel := [12]byte{'s', 'u', 'b', 't', 'r', 'e', 'e', '/', 'v', '1', '\n', 0}
	if string(msg[:12]) != string(expectedLabel[:]) {
		t.Errorf("label mismatch: got %q, want %q", msg[:12], expectedLabel[:])
	}

	// Check cosigner name length prefix.
	nameLen := int(msg[12])
	if nameLen != len("my-witness") {
		t.Errorf("cosigner name length: got %d, want %d", nameLen, len("my-witness"))
	}
	cosignerName := string(msg[13 : 13+nameLen])
	if cosignerName != "my-witness" {
		t.Errorf("cosigner name: got %q, want %q", cosignerName, "my-witness")
	}
}

func TestParseVKeyInvalidType(t *testing.T) {
	// Construct a vkey with an unsupported type byte.
	data := append([]byte{0xFF}, make([]byte, 32)...)
	vkey := "test+00000000+" + base64.StdEncoding.EncodeToString(data)
	if _, _, _, err := ParseVKey(vkey); err == nil {
		t.Error("expected ParseVKey to reject unsupported type byte 0xFF")
	}
}

func TestWriteKeyFilePermissions(t *testing.T) {
	s, err := GenerateKey("test", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	writeKeyFile(t, path, s)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("key file permissions: got %o, want 0600", perm)
	}
}

func TestKeyFileContent(t *testing.T) {
	s, err := GenerateKey("test.example/log", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	writeKeyFile(t, path, s)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	// Line 1 should be a valid vkey.
	if _, _, _, err := ParseVKey(lines[0]); err != nil {
		t.Errorf("line 1 is not a valid vkey: %v", err)
	}
	// Line 2 should be valid base64.
	seed, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Errorf("line 2 is not valid base64: %v", err)
	}
	if len(seed) != 32 {
		t.Errorf("seed length: got %d, want 32", len(seed))
	}
}
