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
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"

	"filippo.io/mldsa"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// This file implements cosignatures over C2SP tlog-checkpoint bodies, used by
// git-ratchet's transparency-log mode.
//
// The distinction from the cosignatures in note.go is confined to ML-DSA-44.
// The Ed25519 cosignature message is generic over the note body, so it is
// identical in both modes. The ML-DSA-44 message is a binary struct with
// fields for the log origin, the tree size and the root hash, which a
// git-checkpoint body has no values for — buildCosignedMessage fills them by
// repurposing the ref line and object hash. A tlog-checkpoint carries exactly
// those three values, so here they can be filled as the specification intends.

// buildTlogCosignedMessage constructs the binary cosigned_message for an
// ML-DSA-44 cosignature over a tlog-checkpoint body, per the C2SP
// tlog-cosignature specification:
//
//	label[12] = "subtree/v1\n\0"
//	cosigner_name<1..2^8-1>  (length-prefixed)
//	timestamp (uint64)
//	log_origin<1..2^8-1>     (length-prefixed)
//	start (uint64) = 0       (full checkpoint)
//	end (uint64)             tree size
//	hash[32]                 root hash
func buildTlogCosignedMessage(cosignerName string, timestamp uint64, body string) ([]byte, error) {
	cp, err := tlog.ParseCheckpoint(body)
	if err != nil {
		return nil, err
	}
	if len(cosignerName) > 255 {
		return nil, fmt.Errorf("cosigner name is too long to encode: %d bytes", len(cosignerName))
	}
	if len(cp.Origin) > 255 {
		return nil, fmt.Errorf("log origin is too long to encode: %d bytes", len(cp.Origin))
	}

	var msg []byte
	msg = append(msg, cosignedMessageLabel...)
	msg = append(msg, byte(len(cosignerName)))
	msg = append(msg, cosignerName...)
	msg = binary.BigEndian.AppendUint64(msg, timestamp)
	msg = append(msg, byte(len(cp.Origin)))
	msg = append(msg, cp.Origin...)
	msg = binary.BigEndian.AppendUint64(msg, 0) // start: a full checkpoint
	msg = binary.BigEndian.AppendUint64(msg, uint64(cp.Size))
	msg = append(msg, cp.Root[:]...)
	return msg, nil
}

// CosignTlogCheckpoint creates a cosignature line for a signed tlog-checkpoint.
// The signer must have RoleCosigner.
//
// Wire format, as in Cosign: keyID(4) || timestamp(8) || signature.
func CosignTlogCheckpoint(signedNote string, signer *Signer) (string, error) {
	if signer.Role != RoleCosigner {
		return "", fmt.Errorf("CosignTlogCheckpoint requires a cosigner key, got origin")
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}
	if _, err := tlog.ParseCheckpoint(body); err != nil {
		return "", fmt.Errorf("not a tlog checkpoint: %w", err)
	}

	timestamp := uint64(time.Now().Unix())

	var sig []byte
	switch signer.SigType {
	case Ed25519Cosigner:
		sig, err = signer.signer.Sign(nil, []byte(ed25519CosignMessage(timestamp, body)), crypto.Hash(0))
		if err != nil {
			return "", fmt.Errorf("Ed25519 cosign: %w", err)
		}

	case MLDSA44:
		msg, err := buildTlogCosignedMessage(signer.Name, timestamp, body)
		if err != nil {
			return "", fmt.Errorf("building cosigned message: %w", err)
		}
		sig, err = signer.signer.Sign(nil, msg, &mldsa.Options{})
		if err != nil {
			return "", fmt.Errorf("ML-DSA-44 cosign: %w", err)
		}

	default:
		return "", fmt.Errorf("unsupported cosigner signature type: 0x%02x", signer.SigType)
	}

	var raw []byte
	raw = append(raw, signer.hash[:]...)
	raw = binary.BigEndian.AppendUint64(raw, timestamp)
	raw = append(raw, sig...)

	return SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw), nil
}

// VerifyTlogCosignature verifies a witness cosignature over a tlog-checkpoint
// body against a public key.
func VerifyTlogCosignature(body, sigLine string, pub crypto.PublicKey, sigType SigType, cosignerName string) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}

	switch sigType {
	case Ed25519Cosigner:
		if len(raw) < 4+8+ed25519SigSize {
			return fmt.Errorf("Ed25519 cosignature too short")
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected Ed25519 public key")
		}
		timestamp := binary.BigEndian.Uint64(raw[4 : 4+8])
		if !ed25519.Verify(edPub, []byte(ed25519CosignMessage(timestamp, body)), raw[4+8:]) {
			return fmt.Errorf("cosignature verification failed")
		}

	case MLDSA44:
		if len(raw) < 4+8+mldsa44SigSize {
			return fmt.Errorf("ML-DSA-44 cosignature too short")
		}
		mlPub, ok := pub.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ML-DSA-44 public key")
		}
		timestamp := binary.BigEndian.Uint64(raw[4 : 4+8])
		msg, err := buildTlogCosignedMessage(cosignerName, timestamp, body)
		if err != nil {
			return fmt.Errorf("building cosigned message: %w", err)
		}
		if err := mldsa.Verify(mlPub, msg, raw[4+8:], &mldsa.Options{}); err != nil {
			return fmt.Errorf("cosignature verification failed: %w", err)
		}

	default:
		return fmt.Errorf("unsupported cosigner signature type: 0x%02x", sigType)
	}
	return nil
}

// ed25519CosignMessage returns the message an Ed25519 cosignature covers, per
// the tlog-cosignature specification. It is generic over the note body, so it
// is shared by both checkpoint formats.
func ed25519CosignMessage(timestamp uint64, body string) string {
	return cosignatureV1Prefix + "\n" +
		"time " + strconv.FormatUint(timestamp, 10) + "\n" +
		body
}
