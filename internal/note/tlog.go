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
	"encoding/base64"
	"fmt"
	"strconv"

	fnote "github.com/transparency-dev/formats/note"
	sumdbnote "golang.org/x/mod/sumdb/note"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

// Signatures over C2SP tlog-checkpoint notes are produced and verified by
// github.com/transparency-dev/formats, not by the constructions in note.go.
//
// C2SP signed-note assigns 0x06 only to the ML-DSA-44 cosigned_message, which
// commits to a log origin, a leaf range and a Merkle root, so it is defined
// only over a tlog-checkpoint. A log signing its own checkpoint signs the same
// message a witness would, over [0, size).
//
// Key hashes and verifier keys are encoded identically here and in formats, so
// they pass between the two unconverted.

// TlogCosigner returns a signer that cosigns tlog-checkpoints with this key,
// for handing to a witness implementation that takes note signers.
func TlogCosigner(s *Signer) (sumdbnote.Signer, error) {
	if s.Role != RoleCosigner {
		return nil, fmt.Errorf("TlogCosigner requires a cosigner key, got origin")
	}
	return checkpointSigner(s)
}

// checkpointSigner returns a formats signer for the given key. It signs a
// tlog-checkpoint note body according to the key's algorithm: a plain note
// signature for 0x01, and the timestamped cosigned_message for 0x04 and 0x06.
//
// A KMS-backed key has no local material to render as an skey, so an ML-DSA-44
// one is wrapped as a crypto.Signer instead: formats builds the same
// cosigned_message either way and calls Sign on it, which for a KMS key is a
// remote call. Ed25519 does not need this path; see SignTlogCheckpoint.
func checkpointSigner(s *Signer) (sumdbnote.Signer, error) {
	if len(s.seed) == 0 && s.SigType == MLDSA44 {
		return fnote.NewMLDSASignerFromCrypto(s.Name, s.signer)
	}
	skey, err := s.SKey()
	if err != nil {
		return nil, err
	}
	return fnote.NewSigner(skey)
}

// SignTlogCheckpoint signs a tlog-checkpoint body as the log, returning the
// signed note. The signer must have RoleOrigin.
func SignTlogCheckpoint(body string, signer *Signer) (string, error) {
	if signer.Role != RoleOrigin {
		return "", fmt.Errorf("SignTlogCheckpoint requires an origin key, got cosigner")
	}
	// The ML-DSA-44 signer parses the body as a checkpoint itself, but the
	// Ed25519 one does not, so reject a non-checkpoint body here for both.
	if _, _, err := tlog.ParseCheckpoint(body); err != nil {
		return "", fmt.Errorf("not a tlog checkpoint: %w", err)
	}

	switch signer.SigType {
	case Ed25519Origin:
		// Sign already emits this construction. It must stay: a KMS-backed
		// key has no local seed for SKey to render.
		return Sign(body, signer)

	case MLDSA44:
		s, err := checkpointSigner(signer)
		if err != nil {
			return "", err
		}
		signed, err := sumdbnote.Sign(&sumdbnote.Note{Text: body}, s)
		if err != nil {
			return "", fmt.Errorf("signing checkpoint: %w", err)
		}
		return string(signed), nil

	default:
		return "", fmt.Errorf("unsupported log signature type: 0x%02x", signer.SigType)
	}
}

// CosignTlogCheckpoint creates a cosignature line for a signed tlog-checkpoint.
// The signer must have RoleCosigner.
//
// Wire format, as in Cosign: keyHash(4) || timestamp(8) || signature.
func CosignTlogCheckpoint(signedNote string, signer *Signer) (string, error) {
	if signer.Role != RoleCosigner {
		return "", fmt.Errorf("CosignTlogCheckpoint requires a cosigner key, got origin")
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}
	// The ML-DSA-44 signer parses the body as a checkpoint itself, but the
	// Ed25519 one does not, so reject a non-checkpoint body here for both.
	if _, _, err := tlog.ParseCheckpoint(body); err != nil {
		return "", fmt.Errorf("not a tlog checkpoint: %w", err)
	}

	if signer.SigType == Ed25519Cosigner {
		// As in SignTlogCheckpoint: Cosign emits this construction, and works
		// with KMS-backed keys.
		return Cosign(signedNote, signer)
	}
	if signer.SigType != MLDSA44 {
		return "", fmt.Errorf("unsupported cosigner signature type: 0x%02x", signer.SigType)
	}

	cosigner, err := checkpointSigner(signer)
	if err != nil {
		return "", err
	}
	// The returned signature is timestamp || signature; the key hash is
	// prepended here, as the signed-note wire format requires.
	sig, err := cosigner.Sign([]byte(body))
	if err != nil {
		return "", fmt.Errorf("cosigning checkpoint: %w", err)
	}

	raw := append(append([]byte{}, signer.hash[:]...), sig...)
	return SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw), nil
}

// ed25519CosignMessage returns the message an Ed25519 cosignature covers, per
// the tlog-cosignature specification. It is generic over the note body, and is
// used by the cosignatures in note.go; tlog-checkpoint cosignatures get the
// equivalent from the formats package.
func ed25519CosignMessage(timestamp uint64, body string) string {
	return cosignatureV1Prefix + "\n" +
		"time " + strconv.FormatUint(timestamp, 10) + "\n" +
		body
}
