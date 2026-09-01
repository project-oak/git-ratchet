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
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(skey+"\n"), 0600); err != nil {
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

// The constructions in note.go are Ed25519-only. C2SP signed-note assigns 0x06 to the
// ML-DSA-44 cosigned_message, which commits to a log origin, a leaf range and a
// Merkle root, which a plain note body has none of. See internal/note/tlog.go.
func TestMLDSA44RejectedForGitCheckpoint(t *testing.T) {
	origin, err := GenerateKey("test-origin-pq", MLDSA44, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := GenerateKey("test-witness-pq", MLDSA44, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	body := "example.com refs/heads/main\nabc123\n"
	if _, err := Sign(body, origin); err == nil {
		t.Error("expected Sign to reject an ML-DSA-44 key")
	}

	edOrigin, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(body, edOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Cosign(signed, witness); err == nil {
		t.Error("expected Cosign to reject an ML-DSA-44 key")
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

	if err := VerifyCosignature(noteBody, cosigLine, witness.pub, Ed25519Cosigner); err != nil {
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

	// Sign with Ed25519, try to verify with an ML-DSA-44 key.
	signed, _ := Sign(body, ed)
	_, sigs, _ := ParseSignedNote(signed)
	if err := VerifySignature(body, sigs[0], ml.pub, MLDSA44); err == nil {
		t.Error("expected cross-algorithm verification to fail (Ed25519 sig, ML-DSA key)")
	}
	// And with an Ed25519 key under the wrong type byte.
	if err := VerifySignature(body, sigs[0], ed.pub, Ed25519Cosigner); err == nil {
		t.Error("expected verification to fail under the cosigner type byte")
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
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}

	// The encoding is C2SP signed-note's, which formats parses directly.
	rest, ok := strings.CutPrefix(skey, "PRIVATE+KEY+")
	if !ok {
		t.Fatalf("skey does not start with PRIVATE+KEY+: %q", skey)
	}
	parts := strings.SplitN(rest, "+", 3)
	if len(parts) != 3 {
		t.Fatalf("skey has %d fields after the prefix, want 3: %q", len(parts), skey)
	}
	if parts[0] != "test.example/log" {
		t.Errorf("name: got %q, want %q", parts[0], "test.example/log")
	}

	key, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("key material is not valid base64: %v", err)
	}
	if got := SigType(key[0]); got != Ed25519Origin {
		t.Errorf("algorithm byte: got 0x%02x, want 0x%02x", got, Ed25519Origin)
	}
	if len(key)-1 != 32 {
		t.Errorf("seed length: got %d, want 32", len(key)-1)
	}
}

// TestReadKeyDataRejectsWrongRole covers what the encoding now makes possible:
// the algorithm byte says what a key is for, so a witness key handed to a
// command that wants an origin key is refused rather than reinterpreted as a
// different key with the same seed.
func TestReadKeyDataRejectsWrongRole(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sigType SigType
		made    KeyRole
		readAs  KeyRole
		wantErr string
	}{
		{"origin key read as cosigner", Ed25519Origin, RoleOrigin, RoleCosigner, "is an origin key"},
		{"cosigner key read as origin", Ed25519Cosigner, RoleCosigner, RoleOrigin, "is a cosigner key"},
		// ML-DSA-44 is 0x06 in both roles, so neither is refused.
		{"mldsa origin read as cosigner", MLDSA44, RoleOrigin, RoleCosigner, ""},
		{"mldsa cosigner read as origin", MLDSA44, RoleCosigner, RoleOrigin, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := GenerateKey("test.example/key", tc.sigType, tc.made)
			if err != nil {
				t.Fatal(err)
			}
			skey, err := s.SKey()
			if err != nil {
				t.Fatal(err)
			}
			_, err = ReadKeyData([]byte(skey), tc.readAs)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestReadKeyDataMalformed(t *testing.T) {
	s, err := GenerateKey("test.example/key", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	skey, err := s.SKey()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimPrefix(skey, "PRIVATE+KEY+"), "+", 3)

	for _, tc := range []struct {
		name    string
		skey    string
		wantErr string
	}{
		{"not a private key", s.VKey(), "not a private key"},
		{"too few fields", "PRIVATE+KEY+name+deadbeef", "malformed private key"},
		{"no name", "PRIVATE+KEY++deadbeef+AAA=", "no name"},
		{"bad base64", "PRIVATE+KEY+name+deadbeef+not base64", "decoding private key"},
		{"renamed key", "PRIVATE+KEY+other+" + parts[1] + "+" + parts[2], "does not match key"},
		{"wrong hash", "PRIVATE+KEY+" + parts[0] + "+deadbeef+" + parts[2], "does not match key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadKeyData([]byte(tc.skey), RoleOrigin); err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
