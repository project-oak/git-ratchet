// Package note implements the C2SP signed-note format for git-ratchet checkpoints.
//
// A checkpoint is a signed note with the body:
//
//	<origin> <ref>
//	<commit-hash>
//
// where <ref> is a full Git reference such as refs/heads/<branch> or
// refs/tags/<tag>. Signed with an Ed25519 origin key, and optionally
// cosigned by witnesses.
// See https://c2sp.org/signed-note for the wire format.
package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// KeyType identifies the role of an Ed25519 key in the signing protocol.
// The value doubles as the type byte used in key hashes and vkeys.
type KeyType byte

const (
	// Ed25519Origin is the key type for Ed25519 origin (log) keys
	// per the C2SP signed-note specification.
	Ed25519Origin KeyType = 0x01

	// Ed25519Cosigner is the key type for Ed25519 cosigner keys
	// per the C2SP tlog-cosignature specification.
	Ed25519Cosigner KeyType = 0x04
)

// TODO(ML-DSA-44): To support ML-DSA-44 signatures (type byte 0x06) for both
// origins and cosigners per tlog-checkpoint and tlog-cosignature:
//
//   - Split KeyType into a SigType (the wire type byte: 0x01, 0x04, 0x06) and
//     a KeyRole (origin vs cosigner). Ed25519 has distinct type bytes per role
//     (0x01/0x04), but ML-DSA-44 uses 0x06 for both roles.
//   - Generalise Signer to hold crypto.Signer / crypto.PublicKey interfaces
//     instead of concrete ed25519 types, since ML-DSA-44 keys are 1312-byte
//     public / ~2560-byte private, with 2420-byte signatures.
//   - Update Sign/Cosign to dispatch on SigType for message construction:
//     ML-DSA-44 cosignatures commit to the cosigner name in the signed message
//     (unlike Ed25519).
//   - Update VerifySignature/VerifyCosignature to accept crypto.PublicKey and
//     dispatch on SigType for signature size and verification algorithm.
//   - Update ParseVKey to handle the 1312-byte ML-DSA-44 public key encoding.

// cosignatureV1Prefix is the header prepended to the cosignature message.
const cosignatureV1Prefix = "cosignature/v1"

// SigPrefix is the em dash prefix for signature lines in signed notes.
const SigPrefix = "\u2014 "

// Signer holds an Ed25519 key pair for signing notes.
// The Type field determines the key's role (origin or cosigner), which
// controls key hash computation, vkey formatting, and which signing
// method (Sign vs Cosign) is permitted.
type Signer struct {
	Name string
	Type KeyType
	hash [4]byte
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateKey creates a new random Ed25519 signer of the given type.
func GenerateKey(name string, keyType KeyType) (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return newSigner(name, priv, keyType), nil
}

// NewSigner creates a signer from a name, Ed25519 seed, and key type.
func NewSigner(name string, seed []byte, keyType KeyType) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return newSigner(name, ed25519.NewKeyFromSeed(seed), keyType), nil
}

func newSigner(name string, priv ed25519.PrivateKey, keyType KeyType) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{
		Name: name,
		Type: keyType,
		hash: keyHashWithType(name, pub, byte(keyType)),
		priv: priv,
		pub:  pub,
	}
}

// VKey returns the verifier key string formatted with this signer's key type.
func (s *Signer) VKey() string {
	return formatVKeyWithType(s.Name, s.pub, s.Type)
}

// Seed returns the Ed25519 seed bytes.
func (s *Signer) Seed() []byte {
	return s.priv.Seed()
}

// Sign creates a signed note from a body text.
// The signer must have type Ed25519Origin.
// The body must end with a newline.
func Sign(body string, signer *Signer) (string, error) {
	if signer.Type != Ed25519Origin {
		return "", fmt.Errorf("Sign requires an origin key (type 0x%02x), got 0x%02x", Ed25519Origin, signer.Type)
	}
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	sig := ed25519.Sign(signer.priv, []byte(body))

	var raw []byte
	raw = append(raw, signer.hash[:]...)
	raw = append(raw, sig...)

	line := SigPrefix + signer.Name + " " + base64.StdEncoding.EncodeToString(raw)
	return body + "\n" + line + "\n", nil
}

// Cosign creates a cosignature line for a signed note per the C2SP
// tlog-cosignature specification. The cosignature signs a message consisting
// of "cosignature/v1\ntime <unix-seconds>\n" prepended to the note body.
// The signer must have type Ed25519Cosigner.
func Cosign(signedNote string, signer *Signer) (string, error) {
	if signer.Type != Ed25519Cosigner {
		return "", fmt.Errorf("Cosign requires a cosigner key (type 0x%02x), got 0x%02x", Ed25519Cosigner, signer.Type)
	}

	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}

	timestamp := uint64(time.Now().Unix())

	// Per tlog-cosignature, the signed message is:
	//   cosignature/v1\n
	//   time <decimal timestamp>\n
	//   <checkpoint body>
	cosignMsg := cosignatureV1Prefix + "\n" +
		"time " + strconv.FormatUint(timestamp, 10) + "\n" +
		body

	sig := ed25519.Sign(signer.priv, []byte(cosignMsg))

	// Wire format: keyID(4) || timestamp(8) || signature(64).
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
func VerifySignature(body, sigLine string, pub ed25519.PublicKey) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}
	if len(raw) < 4+ed25519.SignatureSize {
		return fmt.Errorf("signature too short")
	}
	if !ed25519.Verify(pub, []byte(body), raw[4:]) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// VerifyCosignature verifies a witness cosignature line against a public key
// per the C2SP tlog-cosignature specification. The verification reconstructs
// the signed message from the embedded timestamp and the note body.
func VerifyCosignature(body, sigLine string, pub ed25519.PublicKey) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}
	if len(raw) < 4+8+ed25519.SignatureSize {
		return fmt.Errorf("cosignature too short")
	}
	// The raw bytes are: KeyHash(4) || timestamp(8) || signature(64).
	timestamp := binary.BigEndian.Uint64(raw[4 : 4+8])

	// Reconstruct the cosignature message per tlog-cosignature:
	//   cosignature/v1\n
	//   time <decimal timestamp>\n
	//   <checkpoint body>
	cosignMsg := cosignatureV1Prefix + "\n" +
		"time " + strconv.FormatUint(timestamp, 10) + "\n" +
		body

	if !ed25519.Verify(pub, []byte(cosignMsg), raw[4+8:]) {
		return fmt.Errorf("cosignature verification failed")
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

// --- Verifier key format ---

// formatVKeyWithType formats a verifier key with the given key type.
func formatVKeyWithType(name string, pub ed25519.PublicKey, keyType KeyType) string {
	kh := keyHashWithType(name, pub, byte(keyType))
	data := append([]byte{byte(keyType)}, pub...)
	return fmt.Sprintf("%s+%08x+%s", name,
		binary.BigEndian.Uint32(kh[:]),
		base64.StdEncoding.EncodeToString(data))
}

// FormatVKey formats an origin verifier key: name+hexID+base64(0x01||pubkey).
func FormatVKey(name string, pub ed25519.PublicKey) string {
	return formatVKeyWithType(name, pub, Ed25519Origin)
}

// FormatCosignVKey formats a cosigner verifier key: name+hexID+base64(0x04||pubkey).
func FormatCosignVKey(name string, pub ed25519.PublicKey) string {
	return formatVKeyWithType(name, pub, Ed25519Cosigner)
}

// ParseVKey parses a verifier key string, returning the name, key type, and
// public key. Accepts both origin (0x01) and cosigner (0x04) key types.
func ParseVKey(vkey string) (string, KeyType, ed25519.PublicKey, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return "", 0, nil, fmt.Errorf("invalid vkey: %q", vkey)
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", 0, nil, fmt.Errorf("invalid vkey base64: %w", err)
	}
	keyType := KeyType(data[0])
	if len(data) < 1 || (keyType != Ed25519Origin && keyType != Ed25519Cosigner) {
		return "", 0, nil, fmt.Errorf("unsupported key type: 0x%02x", data[0])
	}
	pub := ed25519.PublicKey(data[1:])
	if len(pub) != ed25519.PublicKeySize {
		return "", 0, nil, fmt.Errorf("invalid public key size")
	}
	return parts[0], keyType, pub, nil
}

// KeyHash returns the 4-byte key hash for a name+public-key pair using
// key type 0x01 (Ed25519 origin/log key). This is the value embedded in
// the leading bytes of every origin signature line.
func KeyHash(name string, pub ed25519.PublicKey) [4]byte {
	return keyHashWithType(name, pub, byte(Ed25519Origin))
}

// CosignKeyHash returns the 4-byte key hash for a name+public-key pair using
// key type 0x04 (Ed25519 cosigner key) per the C2SP tlog-cosignature
// specification. This is the value embedded in the leading bytes of every
// cosignature line.
func CosignKeyHash(name string, pub ed25519.PublicKey) [4]byte {
	return keyHashWithType(name, pub, byte(Ed25519Cosigner))
}

// keyHashWithType computes the 4-byte key hash using the given type byte:
//
//	SHA-256(name || "\n" || typeByte || publicKey)[:4]
func keyHashWithType(name string, pub ed25519.PublicKey, typeByte byte) [4]byte {
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{typeByte})
	h.Write(pub)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

// --- Key file I/O ---

// ReadKeyFile reads a signer from a key file (line 1: name, line 2: base64 seed).
// The caller specifies the key type to assign to the resulting signer.
func ReadKeyFile(path string, keyType KeyType) (*Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) != 2 {
		return nil, fmt.Errorf("key file must have 2 lines: name and base64 seed")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return nil, fmt.Errorf("decoding seed: %w", err)
	}
	return NewSigner(strings.TrimSpace(lines[0]), seed, keyType)
}

// WriteKeyFile writes a signer's private key to a file.
func WriteKeyFile(path string, s *Signer) error {
	content := s.Name + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}
