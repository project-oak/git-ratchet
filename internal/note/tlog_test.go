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
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

func testTlogCheckpoint() tlog.Checkpoint {
	return tlog.Checkpoint{
		Origin: "github.com/example/repo",
		Size:   7,
		Root:   tlog.HashLeaf([]byte("root")),
	}
}

// signTestCheckpoint produces a signed tlog-checkpoint note.
func signTestCheckpoint(t *testing.T, sigType SigType) string {
	t.Helper()
	signer, err := GenerateKey("test-origin", sigType, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(testTlogCheckpoint().Body(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestCosignTlogCheckpointRoundTrip covers both signature algorithms.
func TestCosignTlogCheckpointRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name      string
		originSig SigType
		cosigSig  SigType
	}{
		{"ed25519", Ed25519Origin, Ed25519Cosigner},
		{"mldsa44", MLDSA44, MLDSA44},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := signTestCheckpoint(t, tc.originSig)

			cosigner, err := GenerateKey("test-witness", tc.cosigSig, RoleCosigner)
			if err != nil {
				t.Fatal(err)
			}
			cosigLine, err := CosignTlogCheckpoint(signed, cosigner)
			if err != nil {
				t.Fatalf("CosignTlogCheckpoint: %v", err)
			}

			body, err := ExtractBody(signed)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyTlogCosignature(body, cosigLine, cosigner.pub, cosigner.SigType, cosigner.Name); err != nil {
				t.Errorf("VerifyTlogCosignature: %v", err)
			}
		})
	}
}

// TestVerifyTlogCosignatureRejectsTamperedBody checks that the cosignature is
// bound to the checkpoint contents, not just to the origin.
func TestVerifyTlogCosignatureRejectsTamperedBody(t *testing.T) {
	for _, sigType := range []SigType{Ed25519Cosigner, MLDSA44} {
		originType := Ed25519Origin
		if sigType == MLDSA44 {
			originType = MLDSA44
		}
		signed := signTestCheckpoint(t, originType)

		cosigner, err := GenerateKey("test-witness", sigType, RoleCosigner)
		if err != nil {
			t.Fatal(err)
		}
		cosigLine, err := CosignTlogCheckpoint(signed, cosigner)
		if err != nil {
			t.Fatal(err)
		}

		// Advance the tree size without re-cosigning.
		cp := testTlogCheckpoint()
		cp.Size = 8
		if err := VerifyTlogCosignature(cp.Body(), cosigLine, cosigner.pub, cosigner.SigType, cosigner.Name); err == nil {
			t.Errorf("sigType 0x%02x: a cosignature should not verify against a different tree size", sigType)
		}
	}
}

// TestTlogCosignedMessageIsConformant checks that the ML-DSA-44 cosigned
// message carries the checkpoint's real origin, size, and root hash.
//
// The git-checkpoint construction in note.go has no such values to work with
// and repurposes the ref line and object hash instead; this is the case where
// the fields mean what the tlog-cosignature specification says they mean.
func TestTlogCosignedMessageIsConformant(t *testing.T) {
	cp := testTlogCheckpoint()
	const cosigner = "test-witness"
	const timestamp = uint64(1700000000)

	msg, err := buildTlogCosignedMessage(cosigner, timestamp, cp.Body())
	if err != nil {
		t.Fatalf("buildTlogCosignedMessage: %v", err)
	}

	var want []byte
	want = append(want, cosignedMessageLabel...)
	want = append(want, byte(len(cosigner)))
	want = append(want, cosigner...)
	want = binary.BigEndian.AppendUint64(want, timestamp)
	want = append(want, byte(len(cp.Origin)))
	want = append(want, cp.Origin...)
	want = binary.BigEndian.AppendUint64(want, 0)               // start
	want = binary.BigEndian.AppendUint64(want, uint64(cp.Size)) // end: the real tree size
	want = append(want, cp.Root[:]...)                          // the real root hash

	if !bytes.Equal(msg, want) {
		t.Errorf("cosigned message mismatch:\ngot  %x\nwant %x", msg, want)
	}
}

// TestCosignTlogCheckpointRejectsGitCheckpointBody checks that the two
// checkpoint formats cannot be crossed over: a git-checkpoint note is not a
// tlog-checkpoint and must not be cosigned as one.
func TestCosignTlogCheckpointRejectsGitCheckpointBody(t *testing.T) {
	signer, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	gitBody := "github.com/example/repo refs/heads/main\n" +
		"4f0f30afb02b71590f0b2e0a67f0b846715e1d04\n"
	signed, err := Sign(gitBody, signer)
	if err != nil {
		t.Fatal(err)
	}

	cosigner, err := GenerateKey("test-witness", Ed25519Cosigner, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CosignTlogCheckpoint(signed, cosigner); err == nil {
		t.Error("expected a git-checkpoint body to be rejected as a tlog checkpoint")
	}
}

// TestCosignTlogCheckpointRequiresCosignerKey mirrors the role check on Cosign.
func TestCosignTlogCheckpointRequiresCosignerKey(t *testing.T) {
	signed := signTestCheckpoint(t, Ed25519Origin)
	originKey, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CosignTlogCheckpoint(signed, originKey)
	if err == nil || !strings.Contains(err.Error(), "cosigner key") {
		t.Errorf("expected a cosigner-key role error, got %v", err)
	}
}
