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
	"errors"
	"fmt"
	"strings"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/tlog"
)

// A log entry is a sequence of newline-terminated lines. The first line names
// the type of statement the entry makes; the rest belong to that type:
//
//	ref-record/v1
//	refs/heads/main 4f0f30afb02b71590f0b2e0a67f0b846715e1d04
//
// Entries are opaque byte strings as far as the log is concerned — bundles
// length-prefix them — so an entry may contain newlines freely and a type is
// free to define however many lines it needs.
//
// # One version, on the type line
//
// The version is part of the type identifier rather than a separate field, and
// there is no second version for the framing. A change in what a statement
// means produces a new type identifier, which older implementations do not
// recognise. The framing itself — first line names the type, the rest is its
// payload — is thin enough that a change to it can be announced the same way.
//
// # Unrecognised types are skipped
//
// An implementation reading a type it does not know ignores that entry. This
// is safe for statements that record state, which is all of them so far,
// because verification does not merely read the log: it reconciles the log
// against the repository. Entries a reader skips leave its idea of the latest
// logged state behind the real ref, and a ref ahead of the log is already a
// failure.
//
// It would not be safe for a statement that withdrew something previously
// recorded, since skipping that would turn a revocation into silence. No such
// statement exists, and adding one would need a way to mark it as
// must-understand that every existing reader already honours — which is to say
// it cannot be added compatibly later. That is a deliberate trade: the cost of
// reserving a marker now was judged higher than the likelihood of ever needing
// one.
const (
	// TypeRefRecord states that a ref pointed at an object.
	TypeRefRecord = "ref-record/v1"

	// MaxEntrySize is the largest entry a tlog-tiles bundle can hold, since
	// bundles length-prefix entries with a uint16.
	MaxEntrySize = 65535
)

// knownTypes is the set of entry types this implementation understands.
var knownTypes = map[string]bool{
	TypeRefRecord: true,
}

// Entry is a single entry in the log.
type Entry struct {
	// raw is the exact byte sequence stored in the log, and the only input to
	// the leaf hash. It is unexported so that no caller can construct an Entry
	// whose bytes disagree with its type.
	raw []byte

	// Type is the entry's statement type, e.g. [TypeRefRecord].
	Type string
}

// Raw returns a copy of the entry's stored bytes.
func (e Entry) Raw() []byte { return bytes.Clone(e.raw) }

// LeafHash returns the RFC 6962 leaf hash of the entry's stored bytes.
func (e Entry) LeafHash() tlog.Hash { return tlog.HashLeaf(e.raw) }

// Known reports whether this implementation understands the entry's type.
func (e Entry) Known() bool { return knownTypes[e.Type] }

// RefRecord is the payload of a [TypeRefRecord] entry: the object a ref
// pointed at when the entry was appended.
//
// Entries record state, not transitions. An entry does not name the ref's
// previous value: the log's ordering already establishes it, and a
// self-asserted predecessor would be a field that verification must not trust
// anyway.
type RefRecord struct {
	Ref    string // full ref path, e.g. "refs/heads/main"
	Object string // lowercase hex object hash the ref pointed at
}

// NewRefRecord builds a ref-record entry ready to append.
func NewRefRecord(ref, object string) (Entry, error) {
	if err := validateRefRecord(ref, object); err != nil {
		return Entry{}, err
	}
	raw := []byte(TypeRefRecord + "\n" + ref + " " + object + "\n")
	if len(raw) > MaxEntrySize {
		return Entry{}, fmt.Errorf("entry is %d bytes, exceeding the %d-byte limit", len(raw), MaxEntrySize)
	}
	return Entry{raw: raw, Type: TypeRefRecord}, nil
}

// AsRefRecord decodes the entry's payload.
func (e Entry) AsRefRecord() (RefRecord, error) {
	if e.Type != TypeRefRecord {
		return RefRecord{}, fmt.Errorf("entry is of type %q, not %q", e.Type, TypeRefRecord)
	}
	lines, err := entryLines(e.raw)
	if err != nil {
		return RefRecord{}, err
	}
	if len(lines) != 2 {
		return RefRecord{}, fmt.Errorf("%s entry has %d lines, want 2", TypeRefRecord, len(lines))
	}

	ref, object, found := strings.Cut(lines[1], " ")
	if !found {
		return RefRecord{}, fmt.Errorf("%s entry: expected \"<ref> <object>\"", TypeRefRecord)
	}
	if err := validateRefRecord(ref, object); err != nil {
		return RefRecord{}, err
	}
	return RefRecord{Ref: ref, Object: object}, nil
}

// validateRefRecord checks the fields a ref-record entry must carry.
//
// The checks are exact rather than tolerant. Anything accepted in more than
// one written form would be a place where two encoders produce different bytes
// for the same statement, and so different leaf hashes.
func validateRefRecord(ref, object string) error {
	if _, err := gitutil.ParseRefKind(ref); err != nil {
		return fmt.Errorf("ref-record entry: %w", err)
	}
	// Git object hashes are hex SHA-1 or SHA-256, matching the lengths the
	// checkpoint format accepts.
	if len(object) != 40 && len(object) != 64 {
		return fmt.Errorf("ref-record entry: object hash %q is %d characters, want 40 or 64", object, len(object))
	}
	if strings.ToLower(object) != object {
		return fmt.Errorf("ref-record entry: object hash %q must be lowercase", object)
	}
	if _, err := hex.DecodeString(object); err != nil {
		return fmt.Errorf("ref-record entry: object hash %q is not hex", object)
	}
	return nil
}

// ParseEntry parses one stored entry.
//
// An entry of an unrecognised type parses successfully and keeps its bytes,
// so that it still contributes its leaf to the tree; only its meaning is
// unavailable. A recognised type is validated here, so a malformed entry is
// caught when the log is read rather than at the point some caller uses it.
func ParseEntry(raw []byte) (Entry, error) {
	lines, err := entryLines(raw)
	if err != nil {
		return Entry{}, err
	}
	entryType := lines[0]
	if entryType == "" {
		return Entry{}, errors.New("malformed log entry: empty type line")
	}
	if strings.ContainsAny(entryType, " \t") {
		return Entry{}, fmt.Errorf("malformed log entry: type %q contains whitespace", entryType)
	}

	e := Entry{raw: bytes.Clone(raw), Type: entryType}
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
	case TypeRefRecord:
		_, err := e.AsRefRecord()
		return err
	default:
		return nil
	}
}

// entryLines splits an entry into its lines, enforcing the framing rules that
// keep the encoding canonical: every line is newline-terminated, including the
// last, and no line carries a carriage return or trailing space.
func entryLines(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("malformed log entry: empty")
	}
	if len(raw) > MaxEntrySize {
		return nil, fmt.Errorf("malformed log entry: %d bytes exceeds the %d-byte limit", len(raw), MaxEntrySize)
	}
	if raw[len(raw)-1] != '\n' {
		return nil, errors.New("malformed log entry: must end with a newline")
	}
	lines := strings.Split(string(raw[:len(raw)-1]), "\n")
	for i, line := range lines {
		if strings.ContainsRune(line, '\r') {
			return nil, fmt.Errorf("malformed log entry: line %d contains a carriage return", i+1)
		}
		if line != strings.TrimRight(line, " \t") {
			return nil, fmt.Errorf("malformed log entry: line %d has trailing whitespace", i+1)
		}
	}
	return lines, nil
}
