// Package note implements the C2SP signed-note format for git-ratchet checkpoints.
//
// A checkpoint is a signed note with the body:
//
//	<origin> refs/heads/<branch>
//	<commit-hash>
//
// Signed with an Ed25519 origin key, and optionally cosigned by witnesses.
// See https://c2sp.org/signed-note for the wire format.
package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"
)

// SigPrefix is the em dash prefix for signature lines in signed notes.
const SigPrefix = "\u2014 "

// Signer holds an Ed25519 key pair for signing notes.
type Signer struct {
	Name string
	hash [4]byte
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// GenerateKey creates a new random Ed25519 signer.
func GenerateKey(name string) (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return newSigner(name, priv), nil
}

// NewSigner creates a signer from a name and Ed25519 seed.
func NewSigner(name string, seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed size: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return newSigner(name, ed25519.NewKeyFromSeed(seed)), nil
}

func newSigner(name string, priv ed25519.PrivateKey) *Signer {
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{
		Name: name,
		hash: KeyHash(name, pub),
		priv: priv,
		pub:  pub,
	}
}

// VKey returns the verifier key string (name+hexID+base64key).
func (s *Signer) VKey() string {
	return FormatVKey(s.Name, s.pub)
}

// Seed returns the Ed25519 seed bytes.
func (s *Signer) Seed() []byte {
	return s.priv.Seed()
}

// Sign creates a signed note from a body text.
// The body must end with a newline.
func Sign(body string, signer *Signer) (string, error) {
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

// Cosign creates a cosignature line for a signed note.
// The cosignature covers the note body and includes a timestamp.
func Cosign(signedNote string, signer *Signer) (string, error) {
	body, err := ExtractBody(signedNote)
	if err != nil {
		return "", fmt.Errorf("extracting body: %w", err)
	}

	sig := ed25519.Sign(signer.priv, []byte(body))

	var raw []byte
	raw = append(raw, signer.hash[:]...)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
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

// VerifyCosignature verifies a witness cosignature line against a public key.
func VerifyCosignature(body, sigLine string, pub ed25519.PublicKey) error {
	raw, err := DecodeSigLine(sigLine)
	if err != nil {
		return err
	}
	if len(raw) < 4+8+ed25519.SignatureSize {
		return fmt.Errorf("cosignature too short")
	}
	// Cosignature is over the body, same as origin signature.
	// The raw bytes are: KeyHash(4) || timestamp(8) || signature.
	if !ed25519.Verify(pub, []byte(body), raw[4+8:]) {
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

// FormatVKey formats a verifier key: name+hexID+base64(0x01||pubkey).
func FormatVKey(name string, pub ed25519.PublicKey) string {
	kh := KeyHash(name, pub)
	data := append([]byte{0x01}, pub...)
	return fmt.Sprintf("%s+%08x+%s", name,
		binary.BigEndian.Uint32(kh[:]),
		base64.StdEncoding.EncodeToString(data))
}

// ParseVKey parses a verifier key string, returning the name and public key.
func ParseVKey(vkey string) (string, ed25519.PublicKey, error) {
	parts := strings.SplitN(vkey, "+", 3)
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("invalid vkey: %q", vkey)
	}
	data, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, fmt.Errorf("invalid vkey base64: %w", err)
	}
	if len(data) < 1 || data[0] != 0x01 {
		return "", nil, fmt.Errorf("unsupported key type: 0x%02x", data[0])
	}
	pub := ed25519.PublicKey(data[1:])
	if len(pub) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("invalid public key size")
	}
	return parts[0], pub, nil
}

// KeyHash returns the 4-byte key hash for a name+public-key pair.
// This is the value embedded in the leading bytes of every signature line
// produced by a signer with those credentials.
func KeyHash(name string, pub ed25519.PublicKey) [4]byte {
	h := sha256.New()
	h.Write([]byte(name + "\n"))
	h.Write([]byte{0x01}) // Ed25519
	h.Write(pub)
	var id [4]byte
	copy(id[:], h.Sum(nil)[:4])
	return id
}

// --- Key file I/O ---

// ReadKeyFile reads a signer from a key file (line 1: name, line 2: base64 seed).
func ReadKeyFile(path string) (*Signer, error) {
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
	return NewSigner(strings.TrimSpace(lines[0]), seed)
}

// WriteKeyFile writes a signer's private key to a file.
func WriteKeyFile(path string, s *Signer) error {
	content := s.Name + "\n" + base64.StdEncoding.EncodeToString(s.Seed()) + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}
