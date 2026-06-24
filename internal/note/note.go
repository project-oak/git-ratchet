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

// Package note implements the C2SP signed-note format for git-ratchet checkpoints.
//
// A checkpoint is a signed note with the body:
//
//	<origin> <ref>
//	<commit-hash>
//
// where <ref> is a full Git reference such as refs/heads/<branch> or
// refs/tags/<tag>. Signed with an Ed25519 or ML-DSA-44 origin key, and
// optionally cosigned by witnesses.
// See https://c2sp.org/signed-note for the wire format.
package note

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/mldsa"
)

// SigType is the wire type byte used in key hashes and vkeys.
// Ed25519 has distinct type bytes per role (0x01 for origin, 0x04 for
// cosigner), but ML-DSA-44 uses 0x06 for both roles.
type SigType byte

const (
	// Ed25519Origin is the type byte for Ed25519 origin (log) keys
	// per the C2SP signed-note specification.
	Ed25519Origin SigType = 0x01

	// Ed25519Cosigner is the type byte for Ed25519 cosigner keys
	// per the C2SP tlog-cosignature specification.
	Ed25519Cosigner SigType = 0x04

	// MLDSA44 is the type byte for ML-DSA-44 keys (both origin
	// and cosigner) per the C2SP tlog-checkpoint and tlog-cosignature
	// specifications.
	MLDSA44 SigType = 0x06
)

// KeyRole distinguishes origin (log) keys from cosigner (witness) keys.
type KeyRole int

const (
	RoleOrigin KeyRole = iota
	RoleCosigner
)

// cosignatureV1Prefix is the header prepended to Ed25519 cosignature messages.
const cosignatureV1Prefix = "cosignature/v1"

// cosignedMessageLabel is the 12-byte label for ML-DSA-44 cosigned messages.
const cosignedMessageLabel = "subtree/v1\n\x00"

// SigPrefix is the em dash prefix for signature lines in signed notes.
const SigPrefix = "\u2014 "

// Ed25519 sizes for convenience.
const (
	ed25519PubKeySize = ed25519.PublicKeySize // 32
	ed25519SigSize    = ed25519.SignatureSize // 64
	ed25519SeedSize   = ed25519.SeedSize      // 32
)

// ML-DSA-44 sizes.
var (
	mldsa44PubKeySize = mldsa.MLDSA44().PublicKeySize() // 1312
	mldsa44SigSize    = mldsa.MLDSA44().SignatureSize() // 2420
	mldsa44SeedSize   = mldsa.PrivateKeySize            // 32
)

// Signer holds a key pair for signing notes.
// The SigType and Role fields determine signing behaviour.
type Signer struct {
	Name    string
	SigType SigType
	Role    KeyRole
	hash    [4]byte
	signer  crypto.Signer
	pub     crypto.PublicKey
	seed    []byte // 32-byte seed (Ed25519 or ML-DSA-44)
}

// GenerateKey creates a new random signer with the given algorithm and role.
func GenerateKey(name string, sigType SigType, role KeyRole) (*Signer, error) {
	switch sigType {
	case Ed25519Origin, Ed25519Cosigner:
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return nil, err
		}
		return newEd25519Signer(name, priv, sigType, role), nil
	case MLDSA44:
		priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
		if err != nil {
			return nil, err
		}
		return newMLDSA44Signer(name, priv, role), nil
	default:
		return nil, fmt.Errorf("unsupported signature type: 0x%02x", sigType)
	}
}

// NewSigner creates a signer from a name, 32-byte seed, signature type, and role.
func NewSigner(name string, seed []byte, sigType SigType, role KeyRole) (*Signer, error) {
	switch sigType {
	case Ed25519Origin, Ed25519Cosigner:
		if len(seed) != ed25519SeedSize {
			return nil, fmt.Errorf("invalid Ed25519 seed size: got %d, want %d", len(seed), ed25519SeedSize)
		}
		return newEd25519Signer(name, ed25519.NewKeyFromSeed(seed), sigType, role), nil
	case MLDSA44:
		if len(seed) != mldsa44SeedSize {
			return nil, fmt.Errorf("invalid ML-DSA-44 seed size: got %d, want %d", len(seed), mldsa44SeedSize)
		}
		priv, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
		if err != nil {
			return nil, fmt.Errorf("creating ML-DSA-44 key: %w", err)
		}
		return newMLDSA44Signer(name, priv, role), nil
	default:
		return nil, fmt.Errorf("unsupported signature type: 0x%02x", sigType)
	}
}

func newEd25519Signer(name string, priv ed25519.PrivateKey, sigType SigType, role KeyRole) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{
		Name:    name,
		SigType: sigType,
		Role:    role,
		hash:    keyHash(name, pubKeyBytes(pub), byte(sigType)),
		signer:  priv,
		pub:     pub,
		seed:    priv.Seed(),
	}
}

func newMLDSA44Signer(name string, priv *mldsa.PrivateKey, role KeyRole) *Signer {
	pub := priv.PublicKey()
	return &Signer{
		Name:    name,
		SigType: MLDSA44,
		Role:    role,
		hash:    keyHash(name, pub.Bytes(), byte(MLDSA44)),
		signer:  priv,
		pub:     pub,
		seed:    priv.Bytes(),
	}
}

// VKey returns the verifier key string: name+hexID+base64(typeByte||pubkey).
func (s *Signer) VKey() string {
	return FormatVKey(s.Name, s.pub, s.SigType)
}

// Seed returns the 32-byte seed.
func (s *Signer) Seed() []byte {
	return s.seed
}

// Sign creates a signed note from a body text.
// The signer must have RoleOrigin.
// The body must end with a newline.
func Sign(body string, signer *Signer) (string, error) {
	if signer.Role != RoleOrigin {
		return "", fmt.Errorf("Sign requires an origin key, got cosigner")
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}

	var sig []byte
	var err error

	switch signer.SigType {
	case Ed25519Origin:
		sig, err = signer.signer.Sign(nil, []byte(body), crypto.Hash(0))
		if err != nil {
			return "", fmt.Errorf("Ed25519 sign: %w", err)
		}
	case MLDSA44:
		sig, err = signer.signer.Sign(nil, []byte(body), &mldsa.Options{})
		if err != nil {
			return "", fmt.Errorf("ML-DSA-44 sign: %w", err)
		}
	default:
		return "", fmt.Errorf("unsupported origin signature type: 0x%02x", signer.SigType)
	}

	var raw []byte
	raw = append(raw, signer.hash[:]...)
	raw = append(raw, sig...)

	line := SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw)
	return body + "\n" + line + "\n", nil
}

// Cosign creates a cosignature line for a signed note.
// The signer must have RoleCosigner.
//
// For Ed25519: per tlog-cosignature, signs "cosignature/v1\ntime <unix>\n<body>".
// Wire format: keyID(4) || timestamp(8) || signature(64).
//
// For ML-DSA-44: per tlog-cosignature, signs a binary cosigned_message struct.
// Wire format: keyID(4) || timestamp(8) || signature(2420).
func Cosign(signedNote string, signer *Signer) (string, error) {
	if signer.Role != RoleCosigner {
		return "", fmt.Errorf("Cosign requires a cosigner key, got origin")
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}

	timestamp := uint64(time.Now().Unix())

	var sig []byte

	switch signer.SigType {
	case Ed25519Cosigner:
		// Per tlog-cosignature, the signed message for Ed25519 is:
		//   cosignature/v1\n
		//   time <decimal timestamp>\n
		//   <checkpoint body>
		cosignMsg := cosignatureV1Prefix + "\n" +
			"time " + strconv.FormatUint(timestamp, 10) + "\n" +
			body
		sig, err = signer.signer.Sign(nil, []byte(cosignMsg), crypto.Hash(0))
		if err != nil {
			return "", fmt.Errorf("Ed25519 cosign: %w", err)
		}

	case MLDSA44:
		// Per tlog-cosignature, the signed message for ML-DSA-44 is
		// a binary cosigned_message struct:
		//   label[12] = "subtree/v1\n\0"
		//   cosigner_name<1..2^8-1>  (length-prefixed)
		//   timestamp (uint64)
		//   log_origin<1..2^8-1>     (length-prefixed)
		//   start (uint64) = 0       (full checkpoint)
		//   end (uint64)
		//   hash[32]
		cosignMsg, err := buildCosignedMessage(signer.Name, timestamp, body)
		if err != nil {
			return "", fmt.Errorf("building cosigned message: %w", err)
		}
		sig, err = signer.signer.Sign(nil, cosignMsg, &mldsa.Options{})
		if err != nil {
			return "", fmt.Errorf("ML-DSA-44 cosign: %w", err)
		}

	default:
		return "", fmt.Errorf("unsupported cosigner signature type: 0x%02x", signer.SigType)
	}

	// Wire format: keyID(4) || timestamp(8) || signature.
	var raw []byte
	raw = append(raw, signer.hash[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestamp)
	raw = append(raw, ts[:]...)
	raw = append(raw, sig...)

	return SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw), nil
}

// buildCosignedMessage constructs the binary cosigned_message for ML-DSA-44
// cosignatures per the C2SP tlog-cosignature specification.
//
// The body is a checkpoint body like "<origin> <ref>\n<commit>\n".
// We parse the origin line and the tree hash/size from it.
// For git-ratchet checkpoints, the body format is:
//
//	<origin> <ref>\n
//	<commit-hash>\n
//
// The tlog-cosignature spec defines the cosigned_message for full checkpoints
// (start=0) where end is the tree size and hash is the root hash.
// Since git-ratchet checkpoints don't have a tree size or Merkle root,
// we use the commit hash as the 32-byte hash and set end=0.
func buildCosignedMessage(cosignerName string, timestamp uint64, body string) ([]byte, error) {
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("checkpoint body too short")
	}

	// Origin is the first line (e.g., "example.com/log refs/heads/main").
	origin := lines[0]

	// The commit hash line. For the binary message we need a 32-byte hash.
	// If the commit is a hex-encoded SHA-1 (40 chars) or SHA-256 (64 chars),
	// we SHA-256 it to get a fixed 32-byte value.
	commitHash := strings.TrimSpace(lines[1])
	h := sha256.Sum256([]byte(commitHash))

	var msg []byte
	// label[12]
	msg = append(msg, cosignedMessageLabel...)
	// cosigner_name<1..2^8-1>: length byte + name
	msg = append(msg, byte(len(cosignerName)))
	msg = append(msg, []byte(cosignerName)...)
	// timestamp (uint64 big-endian)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestamp)
	msg = append(msg, ts[:]...)
	// log_origin<1..2^8-1>: length byte + origin
	msg = append(msg, byte(len(origin)))
	msg = append(msg, []byte(origin)...)
	// start (uint64) = 0 for full checkpoint
	var zero [8]byte
	msg = append(msg, zero[:]...)
	// end (uint64) = 0 (git-ratchet doesn't track tree sizes)
	msg = append(msg, zero[:]...)
	// hash[32]
	msg = append(msg, h[:]...)

	return msg, nil
}

// AppendSignature appends a signature line to a signed note.
func AppendSignature(signedNote, sigLine string) string {
	if !strings.HasSuffix(signedNote, "\n") {
		signedNote += "\n"
	}
	return signedNote + sigLine + "\n"
}

// ExtractBody returns the body text from a signed note (everything before
// the blank line separating body from signatures).
func ExtractBody(note string) (string, error) {
	idx := strings.Index(note, "\n\n"+SigPrefix)
	if idx < 0 {
		return "", fmt.Errorf("no signatures found in note")
	}
	return note[:idx+1], nil // include trailing \n
}

// ParseSignedNote splits a signed note into body and signature lines.
func ParseSignedNote(data string) (body string, sigLines []string, err error) {
	body, err = ExtractBody(data)
	if err != nil {
		return "", nil, err
	}
	rest := data[len(body)+1:] // skip the extra \n separator
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(line, SigPrefix) {
			sigLines = append(sigLines, line)
		}
	}
	return body, sigLines, nil
}

// VerifySignature verifies an origin signature line against a public key.
func VerifySignature(body, sigLine string, pub crypto.PublicKey, sigType SigType) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}

	switch sigType {
	case Ed25519Origin:
		if len(raw) < 4+ed25519SigSize {
			return fmt.Errorf("Ed25519 signature too short")
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("expected Ed25519 public key")
		}
		if !ed25519.Verify(edPub, []byte(body), raw[4:]) {
			return fmt.Errorf("signature verification failed")
		}

	case MLDSA44:
		if len(raw) < 4+mldsa44SigSize {
			return fmt.Errorf("ML-DSA-44 signature too short")
		}
		mlPub, ok := pub.(*mldsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ML-DSA-44 public key")
		}
		if err := mldsa.Verify(mlPub, []byte(body), raw[4:], &mldsa.Options{}); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}

	default:
		return fmt.Errorf("unsupported origin signature type: 0x%02x", sigType)
	}
	return nil
}

// VerifyCosignature verifies a witness cosignature line against a public key.
func VerifyCosignature(body, sigLine string, pub crypto.PublicKey, sigType SigType, cosignerName string) error {
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
		cosignMsg := cosignatureV1Prefix + "\n" +
			"time " + strconv.FormatUint(timestamp, 10) + "\n" +
			body
		if !ed25519.Verify(edPub, []byte(cosignMsg), raw[4+8:]) {
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
		cosignMsg, err := buildCosignedMessage(cosignerName, timestamp, body)
		if err != nil {
			return fmt.Errorf("building cosigned message: %w", err)
		}
		if err := mldsa.Verify(mlPub, cosignMsg, raw[4+8:], &mldsa.Options{}); err != nil {
			return fmt.Errorf("cosignature verification failed: %w", err)
		}

	default:
		return fmt.Errorf("unsupported cosigner signature type: 0x%02x", sigType)
	}
	return nil
}

// SigName extracts the signer name from a signature line.
func SigName(sigLine string) (string, error) {
	if !strings.HasPrefix(sigLine, SigPrefix) {
		return "", fmt.Errorf("not a signature line")
	}
	rest := strings.TrimPrefix(sigLine, SigPrefix)
	if i := strings.Index(rest, " "); i > 0 {
		return rest[:i], nil
	}
	return "", fmt.Errorf("invalid signature line format")
}

// DecodeSigLine decodes a signature line and returns the raw bytes
// (KeyHash[4] || … || signature). The first 4 bytes are the key hash as
// embedded by the signer; callers can compare them against an expected hash
// for defence-in-depth key-confusion protection.
func DecodeSigLine(line string) ([]byte, error) {
	if !strings.HasPrefix(line, SigPrefix) {
		return nil, fmt.Errorf("not a signature line")
	}
	rest := strings.TrimPrefix(line, SigPrefix)
	i := strings.Index(rest, " ")
	if i < 0 {
		return nil, fmt.Errorf("invalid signature line")
	}
	return base64.StdEncoding.DecodeString(rest[i+1:])
}

// FormatVKey formats a verifier key: name+hexID+base64(typeByte||pubkey).
func FormatVKey(name string, pub crypto.PublicKey, sigType SigType) string {
	pubBytes := pubKeyBytes(pub)
	kh := keyHash(name, pubBytes, byte(sigType))
	data := append([]byte{byte(sigType)}, pubBytes...)
	return fmt.Sprintf("%s+%08x+%s", name,
		binary.BigEndian.Uint32(kh[:]),
		base64.StdEncoding.EncodeToString(data))
}

// ParseVKey parses a verifier key string, returning the name, sig type, and
// public key. Accepts Ed25519 origin (0x01), Ed25519 cosigner (0x04), and
// ML-DSA-44 (0x06) key types.
func ParseVKey(vkey string) (string, SigType, crypto.PublicKey, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return "", 0, nil, fmt.Errorf("invalid vkey: %q", vkey)
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", 0, nil, fmt.Errorf("invalid vkey base64: %w", err)
	}
	if len(data) < 1 {
		return "", 0, nil, fmt.Errorf("empty vkey data")
	}
	sigType := SigType(data[0])
	keyData := data[1:]

	switch sigType {
	case Ed25519Origin, Ed25519Cosigner:
		if len(keyData) != ed25519PubKeySize {
			return "", 0, nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(keyData), ed25519PubKeySize)
		}
		return parts[0], sigType, ed25519.PublicKey(keyData), nil

	case MLDSA44:
		if len(keyData) != mldsa44PubKeySize {
			return "", 0, nil, fmt.Errorf("invalid ML-DSA-44 public key size: got %d, want %d", len(keyData), mldsa44PubKeySize)
		}
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), keyData)
		if err != nil {
			return "", 0, nil, fmt.Errorf("parsing ML-DSA-44 public key: %w", err)
		}
		return parts[0], sigType, pub, nil

	default:
		return "", 0, nil, fmt.Errorf("unsupported key type: 0x%02x", data[0])
	}
}

// KeyHash returns the 4-byte key hash for a name + public key + sig type.
//
//	SHA-256(name || "\n" || typeByte || publicKey)[:4]
func KeyHash(name string, pub crypto.PublicKey, sigType SigType) [4]byte {
	return keyHash(name, pubKeyBytes(pub), byte(sigType))
}

func keyHash(name string, pubBytes []byte, typeByte byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{typeByte})
	h.Write(pubBytes)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

// pubKeyBytes returns the raw bytes for a public key.
func pubKeyBytes(pub crypto.PublicKey) []byte {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return []byte(k)
	case *mldsa.PublicKey:
		return k.Bytes()
	default:
		panic(fmt.Sprintf("unsupported public key type: %T", pub))
	}
}

// Key file format:
//   Line 1: vkey string (name+hexID+base64(typeByte||pubkey))
//   Line 2: base64-encoded 32-byte seed

// ReadKeyFile reads a signer from a key file.
// The role is determined by the caller (origin vs cosigner).
func ReadKeyFile(path string, role KeyRole) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) != 2 {
		return nil, fmt.Errorf("key file must have 2 lines: vkey and base64 seed")
	}

	// Parse the vkey to get name, sigType, and public key.
	name, sigType, _, err := ParseVKey(strings.TrimSpace(lines[0]))
	if err != nil {
		return nil, fmt.Errorf("parsing vkey: %w", err)
	}

	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("decoding seed: %w", err)
	}

	// For ML-DSA-44, use the ML-DSA sigType regardless of the caller-specified role.
	// For Ed25519, select the correct sigType based on role.
	if sigType == MLDSA44 {
		return NewSigner(name, seed, MLDSA44, role)
	}
	// Ed25519: pick the correct type byte based on role.
	if role == RoleCosigner {
		sigType = Ed25519Cosigner
	} else {
		sigType = Ed25519Origin
	}
	return NewSigner(name, seed, sigType, role)
}
