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

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// writePolicy writes a policy file in the field order tlog-policy defines.
func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.txt")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// signedCheckpoint builds a tlog-checkpoint signed by origin and cosigned by
// each of the given cosigners, exactly as the checkpoint command does.
func signedCheckpoint(t *testing.T, origin *note.Signer, cosigners ...*note.Signer) string {
	t.Helper()
	cp := tlog.NewCheckpoint(origin.Name, 7, tlog.HashLeaf([]byte("root")))
	signed, err := note.SignTlogCheckpoint(string(cp.Marshal()), origin)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cosigners {
		line, err := note.CosignTlogCheckpoint(signed, c)
		if err != nil {
			t.Fatal(err)
		}
		signed = note.AppendSignature(signed, line)
	}
	return signed
}

func mustKey(t *testing.T, name string, sigType note.SigType, role note.KeyRole) *note.Signer {
	t.Helper()
	s, err := note.GenerateKey(name, sigType, role)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestTlogPolicyAcceptsOurCheckpoint is the compatibility check this package
// exists to make: signatures produced by internal/note must be ones formats
// accepts. Every combination of log and witness algorithm is covered, because
// formats picks each key's construction from its algorithm byte: a plain note
// signature for Ed25519 (0x01), the timestamped cosignature for Ed25519
// witnesses (0x04), and the timestamped cosigned_message for ML-DSA-44 (0x06),
// which is the only construction C2SP assigns to that algorithm — log or
// witness.
//
// What formats does with a checkpoint it rejects is formats' business and is
// not asserted here.
func TestTlogPolicyAcceptsOurCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name      string
		originSig note.SigType
		cosigSig  note.SigType
	}{
		{"ed25519-log-ed25519-witness", note.Ed25519Origin, note.Ed25519Cosigner},
		{"ed25519-log-mldsa44-witness", note.Ed25519Origin, note.MLDSA44},
		{"mldsa44-log-ed25519-witness", note.MLDSA44, note.Ed25519Cosigner},
		{"mldsa44-log-mldsa44-witness", note.MLDSA44, note.MLDSA44},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := mustKey(t, "test-origin", tc.originSig, note.RoleOrigin)
			witness := mustKey(t, "test-witness", tc.cosigSig, note.RoleCosigner)

			path := writePolicy(t, fmt.Sprintf(
				"log %s\nwitness w1 %s https://witness.example\n\nquorum w1\n",
				origin.VKey(), witness.VKey()))
			pol, err := FromPath(path)
			if err != nil {
				t.Fatalf("FromPath: %v", err)
			}
			cp := []byte(signedCheckpoint(t, origin, witness))
			if _, err := pol.Verify(cp); err != nil {
				t.Errorf("Verify rejected our checkpoint: %v", err)
			}

			// A control, not a test of the quorum rule: without our
			// cosignature the same policy is not satisfied, so the assertion
			// above is about the cosignature and not vacuous.
			if pol.Satisfied([]byte(signedCheckpoint(t, origin))) {
				t.Error("policy satisfied without our cosignature; the check above proves nothing")
			}
		})
	}
}

// TestFromPathErrors covers what FromPath itself is responsible for: reading
// the file, and reporting a parse failure against it. The grammar is the
// formats package's to enforce and is tested there.
func TestFromPathErrors(t *testing.T) {
	if _, err := FromPath(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("expected a missing policy file to be an error")
	}
	path := writePolicy(t, "not a policy\n")
	if _, err := FromPath(path); err == nil {
		t.Error("expected a malformed policy to be an error")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("parse error should name the file, got %v", err)
	}
}
