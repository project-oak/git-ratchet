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

package gitlog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// A log entry is one line of compact JSON. Bundles are newline-delimited, so
// an entry may not contain a raw newline; JSON escapes newlines inside
// strings, so compact encoding always satisfies this.
//
// Every entry carries the type of statement it makes, so the log can grow new
// kinds of statement without the existing ones becoming ambiguous:
//
//	{"type":"git-ratchet/ref-update/v1","ref":"refs/heads/main","object":"4f0f…"}
//
// The version is part of the type string rather than a separate field. A
// change in the meaning of a type is therefore a new type, which an
// implementation that predates the change does not recognise — and unrecognised
// types are refused rather than skipped. Old code cannot half-understand a
// newer log.
//
// # Bytes, not values
//
// The Merkle leaf hash is taken over the exact bytes stored in the log, never
// over a re-encoding of the decoded entry. JSON does not define a canonical
// encoding — key order and spacing are free — so re-encoding an entry could
// produce different bytes and thus a different leaf hash, invalidating every
// proof over it. [Entry] therefore keeps the bytes it was parsed from, and
// [Entry.LeafHash] reads only those.
const (
	// TypeRefUpdate states that a ref pointed at an object. It is the only
	// entry type this implementation writes or understands.
	TypeRefUpdate = "git-ratchet/ref-update/v1"
)

// knownTypes is the set of entry types this implementation understands.
// Adding a type here is what makes verification willing to accept it.
var knownTypes = map[string]bool{
	TypeRefUpdate: true,
}

// Entry is a single entry in the log.
type Entry struct {
	// raw is the exact byte sequence stored in the log, and the only input to
	// the leaf hash. It is unexported so that no caller can construct an Entry
	// whose bytes disagree with its fields.
	raw []byte

	// Type is the entry's statement type, e.g. [TypeRefUpdate].
	Type string

	// Critical reports whether an implementation that does not recognise Type
	// must refuse the log rather than skip the entry. It defaults to true when
	// the entry does not say, so an entry is only ever skippable by saying so
	// explicitly.
	Critical bool
}

// Raw returns a copy of the entry's stored bytes.
func (e Entry) Raw() []byte { return bytes.Clone(e.raw) }

// LeafHash returns the RFC 6962 leaf hash of the entry's stored bytes.
func (e Entry) LeafHash() tlog.Hash { return tlog.HashLeaf(e.raw) }

// Known reports whether this implementation understands the entry's type.
func (e Entry) Known() bool { return knownTypes[e.Type] }

// RefUpdate is the payload of a [TypeRefUpdate] entry: the object a ref
// pointed at when the entry was appended.
//
// Entries record state, not transitions. An entry does not name the ref's
// previous value: the log's ordering already establishes it, and a
// self-asserted predecessor would be a field that verification must not trust
// anyway.
type RefUpdate struct {
	Ref    string // full ref path, e.g. "refs/heads/main"
	Object string // hex object hash the ref pointed at
}

// refUpdateJSON is the wire form of a ref-update entry. Field order here is
// the order the encoder emits, and so the order entries appear in the log.
type refUpdateJSON struct {
	Type     string `json:"type"`
	Critical *bool  `json:"critical,omitempty"`
	Ref      string `json:"ref"`
	Object   string `json:"object"`
}

// NewRefUpdate builds a ref-update entry ready to append.
func NewRefUpdate(ref, object string) (Entry, error) {
	if err := validateRefUpdate(ref, object); err != nil {
		return Entry{}, err
	}
	raw, err := json.Marshal(refUpdateJSON{Type: TypeRefUpdate, Ref: ref, Object: object})
	if err != nil {
		return Entry{}, fmt.Errorf("encoding ref-update entry: %w", err)
	}
	return Entry{raw: raw, Type: TypeRefUpdate, Critical: true}, nil
}

// AsRefUpdate decodes the entry's payload. Unknown fields are refused: a field
// this implementation does not know about could carry meaning it would
// silently ignore, and any such change belongs in a new type version.
func (e Entry) AsRefUpdate() (RefUpdate, error) {
	if e.Type != TypeRefUpdate {
		return RefUpdate{}, fmt.Errorf("entry is of type %q, not %q", e.Type, TypeRefUpdate)
	}
	dec := json.NewDecoder(bytes.NewReader(e.raw))
	dec.DisallowUnknownFields()
	var v refUpdateJSON
	if err := dec.Decode(&v); err != nil {
		return RefUpdate{}, fmt.Errorf("decoding ref-update entry: %w", err)
	}
	if err := validateRefUpdate(v.Ref, v.Object); err != nil {
		return RefUpdate{}, err
	}
	return RefUpdate{Ref: v.Ref, Object: v.Object}, nil
}

// validateRefUpdate checks the fields a ref-update entry must carry.
func validateRefUpdate(ref, object string) error {
	if _, err := gitutil.ParseRefKind(ref); err != nil {
		return fmt.Errorf("ref-update entry: %w", err)
	}
	// Git object hashes are hex SHA-1 or SHA-256, matching the lengths the
	// checkpoint format accepts.
	if len(object) != 40 && len(object) != 64 {
		return fmt.Errorf("ref-update entry: object hash %q is %d characters, want 40 or 64", object, len(object))
	}
	if _, err := hex.DecodeString(object); err != nil {
		return fmt.Errorf("ref-update entry: object hash %q is not hex", object)
	}
	return nil
}

// ParseEntry parses one stored log line.
func ParseEntry(line []byte) (Entry, error) {
	if err := checkWellFormedJSON(line); err != nil {
		return Entry{}, fmt.Errorf("malformed log entry: %w", err)
	}

	// The envelope is read leniently: an entry of a type this implementation
	// does not know will carry fields it cannot name, and it still has to be
	// able to read the type and criticality in order to refuse it properly.
	var env struct {
		Type     *string `json:"type"`
		Critical *bool   `json:"critical"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return Entry{}, fmt.Errorf("malformed log entry: %w", err)
	}
	if env.Type == nil || *env.Type == "" {
		return Entry{}, errors.New("malformed log entry: missing type")
	}

	e := Entry{raw: bytes.Clone(line), Type: *env.Type, Critical: true}
	if env.Critical != nil {
		e.Critical = *env.Critical
	}

	// A recognised type is validated now, so a malformed entry is caught when
	// the log is read rather than at the point some caller happens to use it.
	if e.Known() {
		if err := e.validate(); err != nil {
			return Entry{}, err
		}
	}
	return e, nil
}

// validate checks a recognised entry's payload. Extend the switch when adding
// a type to knownTypes.
func (e Entry) validate() error {
	switch e.Type {
	case TypeRefUpdate:
		_, err := e.AsRefUpdate()
		return err
	default:
		return nil
	}
}

// checkWellFormedJSON verifies that data is exactly one JSON object, with no
// trailing content and no object anywhere in it containing a repeated key.
//
// Repeated keys are the reason this exists. JSON parsers disagree about which
// value wins, so an entry carrying a key twice could mean different things to
// two verifiers reading identical bytes — a split view inside a single log.
func checkWellFormedJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("entry must be a JSON object")
	}
	if err := walkObject(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing content after entry")
	}
	return nil
}

// walkObject consumes an object whose opening brace has been read.
func walkObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("expected an object key, got %v", tok)
		}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = struct{}{}
		if err := walkValue(dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // closing brace
	return err
}

// walkValue consumes one value, descending into objects and arrays.
func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // scalar
	}
	switch delim {
	case '{':
		return walkObject(dec)
	case '[':
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // closing bracket
		return err
	default:
		return fmt.Errorf("unexpected %v", delim)
	}
}
