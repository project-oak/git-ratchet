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
	"crypto"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"filippo.io/mldsa"
	flog "github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

const (
	testOrigin = "github.com/example/repo"
	testSize   = 7
)

func testRoot() tlog.Hash { return tlog.HashLeaf([]byte("root")) }

func testCheckpoint() flog.Checkpoint {
	return tlog.NewCheckpoint(testOrigin, testSize, testRoot())
}

// signTestCheckpoint produces a signed tlog-checkpoint note.
func signTestCheckpoint(t *testing.T, sigType SigType) string {
	t.Helper()
	signer, err := GenerateKey("test-origin", sigType, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTlogCheckpoint(string(testCheckpoint().Marshal()), signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// TestKeyEncodingsMatchFormats pins the compatibility the shim in tlog.go
// rests on: our key hash and verifier-key encoding must be the ones the
// formats package computes, or a cosignature we produce would carry a key hash
// no verifier could match.
func TestKeyEncodingsMatchFormats(t *testing.T) {
	for _, sigType := range []SigType{Ed25519Cosigner, MLDSA44} {
		signer, err := GenerateKey("test-witness", sigType, RoleCosigner)
		if err != nil {
			t.Fatal(err)
		}

		vkey := FormatVKey(signer.Name, signer.pub, sigType)
		v, err := fnote.NewVerifier(vkey)
		if err != nil {
			t.Fatalf("sigType 0x%02x: building verifier: %v", sigType, err)
		}
		if got, want := v.KeyHash(), binary.BigEndian.Uint32(signer.hash[:]); got != want {
			t.Errorf("sigType 0x%02x: formats key hash %08x, ours %08x", sigType, got, want)
		}
		if v.Name() != signer.Name {
			t.Errorf("sigType 0x%02x: formats name %q, ours %q", sigType, v.Name(), signer.Name)
		}

		// The signer built through the shim must agree with the verifier
		// built from the matching vkey.
		s, err := checkpointSigner(signer)
		if err != nil {
			t.Fatalf("sigType 0x%02x: checkpointSigner: %v", sigType, err)
		}
		if s.KeyHash() != v.KeyHash() {
			t.Errorf("sigType 0x%02x: signer and verifier key hashes differ", sigType)
		}
	}
}

// TestCosignWireLayout pins the bytes of a cosignature line: the key hash,
// then the timestamp, then the algorithm's signature.
func TestCosignWireLayout(t *testing.T) {
	signed := signTestCheckpoint(t, Ed25519Origin)
	cosigner, err := GenerateKey("test-witness", Ed25519Cosigner, RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	line, err := CosignTlogCheckpoint(signed, cosigner)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := DecodeSigLine(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4+8+ed25519SigSize {
		t.Fatalf("cosignature is %d bytes, want %d", len(raw), 4+8+ed25519SigSize)
	}
	if !bytes.Equal(raw[:4], cosigner.hash[:]) {
		t.Error("cosignature does not begin with the signer's key hash")
	}
	if ts := binary.BigEndian.Uint64(raw[4:12]); ts == 0 {
		t.Error("cosignature carries no timestamp")
	}
}

// TestCosignTlogCheckpointRejectsGitCheckpointBody checks that the two
// note bodies cannot be crossed over: a plain ref-binding note is not a
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
		t.Error("expected a non-checkpoint body to be rejected as a tlog checkpoint")
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

// cosignedMessageV1 builds the tlog-cosignature cosigned_message from the
// specification, independently of the formats package:
//
//	struct {
//	    uint8 label[12] = "subtree/v1\n\0";
//	    opaque cosigner_name<1..2^8-1>;
//	    uint64 timestamp;
//	    opaque log_origin<1..2^8-1>;
//	    uint64 start;
//	    uint64 end;
//	    uint8 hash[32];
//	} cosigned_message;
func cosignedMessageV1(cosignerName string, timestamp uint64, logOrigin string, start, end uint64, hash []byte) []byte {
	var m []byte
	m = append(m, "subtree/v1\n\x00"...)
	m = append(m, byte(len(cosignerName)))
	m = append(m, cosignerName...)
	m = binary.BigEndian.AppendUint64(m, timestamp)
	m = append(m, byte(len(logOrigin)))
	m = append(m, logOrigin...)
	m = binary.BigEndian.AppendUint64(m, start)
	m = binary.BigEndian.AppendUint64(m, end)
	return append(m, hash...)
}

// TestMLDSA44MessageMatchesSpec checks that an ML-DSA-44 signature we produce
// verifies against the cosigned_message the specification defines, reassembled
// here from the checkpoint rather than taken from the signing library.
//
// It covers the log and the witness together, because C2SP assigns no
// identifier to a plain ML-DSA-44 note signature: 0x06 always denotes this
// construction, so a log signing its own checkpoint signs the same message a
// witness would, over the range [0, size).
func TestMLDSA44MessageMatchesSpec(t *testing.T) {
	root := testRoot()
	body := string(testCheckpoint().Marshal())

	for _, tc := range []struct {
		name string
		role KeyRole
		sign func(*Signer) (string, error)
	}{
		{"log", RoleOrigin, func(s *Signer) (string, error) {
			signed, err := SignTlogCheckpoint(body, s)
			if err != nil {
				return "", err
			}
			_, sigLines, err := ParseSignedNote(signed)
			if err != nil {
				return "", err
			}
			return sigLines[0], nil
		}},
		{"witness", RoleCosigner, func(s *Signer) (string, error) {
			signed := signTestCheckpoint(t, Ed25519Origin)
			return CosignTlogCheckpoint(signed, s)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer, err := GenerateKey("example.com/"+tc.name, MLDSA44, tc.role)
			if err != nil {
				t.Fatal(err)
			}
			line, err := tc.sign(signer)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := DecodeSigLine(line)
			if err != nil {
				t.Fatal(err)
			}
			if want := 4 + 8 + mldsa.MLDSA44().SignatureSize(); len(raw) != want {
				t.Fatalf("signature is %d bytes, want %d", len(raw), want)
			}
			if !bytes.Equal(raw[:4], signer.hash[:]) {
				t.Error("signature does not begin with the signer's key hash")
			}

			timestamp := binary.BigEndian.Uint64(raw[4:12])
			if timestamp == 0 {
				t.Error("signature carries no timestamp")
			}
			msg := cosignedMessageV1(signer.Name, timestamp, testOrigin, 0, testSize, root[:])
			pub, ok := signer.pub.(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("expected *mldsa.PublicKey, got %T", signer.pub)
			}
			if err := mldsa.Verify(pub, msg, raw[12:], nil); err != nil {
				t.Errorf("signature does not cover the specified cosigned_message: %v", err)
			}

			// A message naming a different signer must not verify: the
			// construction commits to the cosigner's name.
			other := cosignedMessageV1("example.com/other", timestamp, testOrigin, 0, testSize, root[:])
			if err := mldsa.Verify(pub, other, raw[12:], nil); err == nil {
				t.Error("signature verified under a different cosigner name")
			}
		})
	}
}

// TestSignTlogCheckpointRejectsGitCheckpointBody is the counterpart to the
// cosigning check: a log must not sign a non-checkpoint note as a tlog one.
func TestSignTlogCheckpointRejectsGitCheckpointBody(t *testing.T) {
	signer, err := GenerateKey("test-origin", Ed25519Origin, RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	gitBody := "github.com/example/repo refs/heads/main\n" +
		"4f0f30afb02b71590f0b2e0a67f0b846715e1d04\n"
	if _, err := SignTlogCheckpoint(gitBody, signer); err == nil {
		t.Error("expected a non-checkpoint body to be rejected as a tlog checkpoint")
	}
}

// TestSignTlogCheckpointRoundTrip checks that a log signature verifies under
// the log's own verifier key, for both algorithms.
func TestSignTlogCheckpointRoundTrip(t *testing.T) {
	for _, sigType := range []SigType{Ed25519Origin, MLDSA44} {
		signer, err := GenerateKey("example.com/log", sigType, RoleOrigin)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignTlogCheckpoint(string(testCheckpoint().Marshal()), signer)
		if err != nil {
			t.Fatalf("sigType 0x%02x: %v", sigType, err)
		}
		v, err := fnote.NewVerifier(signer.VKey())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := flog.ParseCheckpoint([]byte(signed), testOrigin, v); err != nil {
			t.Errorf("sigType 0x%02x: %v", sigType, err)
		}

		// A signature over a different tree must not verify.
		other := tlog.NewCheckpoint(testOrigin, testSize+1, testRoot())
		tampered := strings.Replace(signed, string(testCheckpoint().Marshal()), string(other.Marshal()), 1)
		if _, _, _, err := flog.ParseCheckpoint([]byte(tampered), testOrigin, v); err == nil {
			t.Errorf("sigType 0x%02x: signature verified over a different tree size", sigType)
		}
	}
}

// remoteSigner wraps a crypto.Signer and hides everything else, standing in
// for a KMS key: signing is the only operation, and there is no key material
// to read.
type remoteSigner struct{ inner crypto.Signer }

func (r remoteSigner) Public() crypto.PublicKey { return r.inner.Public() }
func (r remoteSigner) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	return r.inner.Sign(rand, msg, opts)
}

// newRemoteMLDSASigner builds a Signer holding no seed, as NewKMSSigner does.
func newRemoteMLDSASigner(t *testing.T, name string, role KeyRole) *Signer {
	t.Helper()
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey()
	return &Signer{
		Name:    name,
		SigType: MLDSA44,
		Role:    role,
		hash:    keyHash(name, pub.Bytes(), byte(MLDSA44)),
		signer:  remoteSigner{priv},
		pub:     pub,
		seed:    nil,
	}
}

// TestCheckpointSignerFromCryptoSigner covers the path a KMS-backed ML-DSA-44 key
// takes. There is no local key material, so SKey cannot render one and the
// signer has to be built from the crypto.Signer instead. The signatures it
// produces must be the same ones a local key produces.
func TestCheckpointSignerFromCryptoSigner(t *testing.T) {
	origin := newRemoteMLDSASigner(t, "test.example/log", RoleOrigin)
	witness := newRemoteMLDSASigner(t, "test.example/witness", RoleCosigner)

	if _, err := origin.SKey(); err == nil {
		t.Fatal("expected SKey to fail for a signer with no local key material")
	}

	body := string(tlog.NewCheckpoint(origin.Name, 7, tlog.HashLeaf([]byte("root"))).Marshal())
	signed, err := SignTlogCheckpoint(body, origin)
	if err != nil {
		t.Fatalf("SignTlogCheckpoint: %v", err)
	}

	cosig, err := CosignTlogCheckpoint(signed, witness)
	if err != nil {
		t.Fatalf("CosignTlogCheckpoint: %v", err)
	}
	full := AppendSignature(signed, cosig)

	// Both signatures must verify under the ordinary verifiers, which know
	// nothing about how the key was held.
	ov, err := fnote.NewVerifier(origin.VKey())
	if err != nil {
		t.Fatalf("origin verifier: %v", err)
	}
	wv, err := fnote.NewVerifier(witness.VKey())
	if err != nil {
		t.Fatalf("witness verifier: %v", err)
	}
	if _, _, n, err := flog.ParseCheckpoint([]byte(full), origin.Name, ov, wv); err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	} else if len(n.Sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(n.Sigs))
	}
}
