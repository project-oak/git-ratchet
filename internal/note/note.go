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
	"strings"
	"time"

	"filippo.io/mldsa"
)

// SigType is the wire type byte used in key hashes and vkeys.
type SigType byte

const (
	// Ed25519Origin is the type byte for Ed25519 origin (log) keys
	// per the C2SP signed-note specification.
	Ed25519Origin SigType = 0x01

	// Ed25519Cosigner is the type byte for Ed25519 cosigner keys
	// per the C2SP tlog-cosignature specification.
	Ed25519Cosigner SigType = 0x04

	// MLDSA44 is the type byte for ML-DSA-44 timestamped (sub)tree
	// cosignatures per the C2SP tlog-cosignature specification.
	//
	// C2SP signed-note assigns no identifier to a plain ML-DSA-44 signature
	// over a note's text, so 0x06 always denotes the cosigned_message
	// construction, whether the signer is the log or a witness. That message
	// commits to a log origin, a leaf range and a Merkle root, so it is
	// well defined only over a tlog-checkpoint. The constructions in this
	// file are generic over a note body and so are Ed25519-only; ML-DSA-44
	// keys are signed and verified in tlog.go, by
	// github.com/transparency-dev/formats.
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

// SKey returns the signer's private key in the C2SP signed-note encoding:
//
//	PRIVATE+KEY+<name>+<key hash>+<base64 of the algorithm byte and the seed>
//
// This is what github.com/transparency-dev/formats parses, so a key written
// this way is read straight into a formats signer with nothing in between.
//
// A KMS-backed signer holds no key material locally and has no SKey.
func (s *Signer) SKey() (string, error) {
	if len(s.seed) == 0 {
		return "", fmt.Errorf("signer %q has no local key material", s.Name)
	}
	key := append([]byte{byte(s.SigType)}, s.seed...)
	return fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s",
		s.Name, binary.BigEndian.Uint32(s.hash[:]), base64.StdEncoding.EncodeToString(key)), nil
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

	if signer.SigType != Ed25519Origin {
		return "", fmt.Errorf("unsupported origin signature type: 0x%02x "+
			"(a plain note signature is Ed25519; an ML-DSA-44 key signs a "+
			"tlog-checkpoint, via SignTlogCheckpoint)", signer.SigType)
	}
	sig, err := signer.signer.Sign(nil, []byte(body), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("Ed25519 sign: %w", err)
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
// Per tlog-cosignature, signs "cosignature/v1\ntime <unix>\n<body>".
// Wire format: keyID(4) || timestamp(8) || signature(64).
//
// Only Ed25519 cosigner keys are accepted. The ML-DSA-44 cosigned message
// commits to a log origin, a leaf range and a Merkle root, which a note has
// only if it is a tlog-checkpoint; see CosignTlogCheckpoint for that case.
func Cosign(signedNote string, signer *Signer) (string, error) {
	if signer.Role != RoleCosigner {
		return "", fmt.Errorf("Cosign requires a cosigner key, got origin")
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}

	if signer.SigType != Ed25519Cosigner {
		return "", fmt.Errorf("unsupported cosigner signature type: 0x%02x "+
			"(this construction is Ed25519; an ML-DSA-44 key cosigns a "+
			"tlog-checkpoint, via CosignTlogCheckpoint)", signer.SigType)
	}

	timestamp := uint64(time.Now().Unix())

	// Per tlog-cosignature, the signed message for Ed25519 is:
	//   cosignature/v1\n
	//   time <decimal timestamp>\n
	//   <checkpoint body>
	sig, err := signer.signer.Sign(nil, []byte(ed25519CosignMessage(timestamp, body)), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("Ed25519 cosign: %w", err)
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

	if sigType != Ed25519Origin {
		return fmt.Errorf("unsupported origin signature type: 0x%02x", sigType)
	}
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
	return nil
}

// VerifyCosignature verifies a witness cosignature line against a public key.
//
// The Ed25519 cosigned message does not commit to the cosigner's name, so the
// caller must have selected pub by the name on the signature line.
func VerifyCosignature(body, sigLine string, pub crypto.PublicKey, sigType SigType) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}

	if sigType != Ed25519Cosigner {
		return fmt.Errorf("unsupported cosigner signature type: 0x%02x", sigType)
	}
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
	return nil
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

// keyHash returns the 4-byte key hash for a name, public key and algorithm
// byte, as C2SP signed-note defines it:
//
//	SHA-256(name || "\n" || typeByte || publicKey)[:4]
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

// ReadKeyData parses a signer from the C2SP signed-note private key encoding;
// see [Signer.SKey].
// The role is determined by the caller (origin vs cosigner).
func ReadKeyData(data []byte, role KeyRole) (*Signer, error) {
	skey := strings.TrimSpace(string(data))
	rest, ok := strings.CutPrefix(skey, "PRIVATE+KEY+")
	if !ok {
		return nil, fmt.Errorf("not a private key: want %q", "PRIVATE+KEY+<name>+<hash>+<base64>")
	}
	// Split from the left and take everything after the key hash as the key
	// material: base64's alphabet includes "+", so only the leading fields can
	// be delimited. A name may not contain "+", as in a vkey.
	parts := strings.SplitN(rest, "+", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed private key: want %q", "PRIVATE+KEY+<name>+<hash>+<base64>")
	}
	name := parts[0]
	if name == "" {
		return nil, fmt.Errorf("malformed private key: no name")
	}

	key, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding private key: %w", err)
	}
	if len(key) < 2 {
		return nil, fmt.Errorf("malformed private key: no key material")
	}
	sigType, seed := SigType(key[0]), key[1:]

	// The algorithm byte says what the key is for, so a key used in the wrong
	// role is rejected rather than reinterpreted. ML-DSA-44 is the exception:
	// signed-note assigns 0x06 to the timestamped cosignature construction and
	// nothing to a plain ML-DSA note signature, so a log signing its own
	// checkpoint uses the same byte a witness does.
	switch sigType {
	case Ed25519Origin:
		if role != RoleOrigin {
			return nil, fmt.Errorf("key %q is an origin key, not a cosigner key", name)
		}
	case Ed25519Cosigner:
		if role != RoleCosigner {
			return nil, fmt.Errorf("key %q is a cosigner key, not an origin key", name)
		}
	case MLDSA44:
	default:
		return nil, fmt.Errorf("unsupported signature type: 0x%02x", sigType)
	}

	signer, err := NewSigner(name, seed, sigType, role)
	if err != nil {
		return nil, err
	}
	// The key hash is derived from the name and the public key, so a mismatch
	// means the file was edited rather than regenerated.
	if want := fmt.Sprintf("%08x", binary.BigEndian.Uint32(signer.hash[:])); parts[1] != want {
		return nil, fmt.Errorf("key hash %s does not match key %q: want %s", parts[1], name, want)
	}
	return signer, nil
}

// ReadKeyFile reads a signer from a key file.
// The role is determined by the caller (origin vs cosigner).
func ReadKeyFile(path string, role KeyRole) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ReadKeyData(data, role)
}
