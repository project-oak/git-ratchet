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
	"encoding/json"
	"strings"
	"testing"
)

const testObject = "4f0f30afb02b71590f0b2e0a67f0b846715e1d04"

func TestNewRefUpdateWireForm(t *testing.T) {
	e, err := NewRefUpdate("refs/heads/main", testObject)
	if err != nil {
		t.Fatal(err)
	}

	want := `{"type":"git-ratchet/ref-update/v1","ref":"refs/heads/main","object":"` + testObject + `"}`
	if got := string(e.Raw()); got != want {
		t.Errorf("wire form =\n  %s\nwant\n  %s", got, want)
	}
	if e.Type != TypeRefUpdate {
		t.Errorf("Type = %q", e.Type)
	}
	if !e.Critical {
		t.Error("entries should be critical unless they say otherwise")
	}
	// An entry must not contain a raw newline: bundles are newline-delimited.
	if bytes.ContainsRune(e.Raw(), '\n') {
		t.Error("entry contains a raw newline")
	}
}

func TestRefUpdateRoundTrip(t *testing.T) {
	e, err := NewRefUpdate("refs/tags/v1.0.0", testObject)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEntry(e.Raw())
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	ru, err := parsed.AsRefUpdate()
	if err != nil {
		t.Fatalf("AsRefUpdate: %v", err)
	}
	if ru.Ref != "refs/tags/v1.0.0" || ru.Object != testObject {
		t.Errorf("round trip = %+v", ru)
	}
}

// TestLeafHashUsesStoredBytes is the property that makes JSON safe here: the
// leaf hash must come from the bytes the log holds, not from re-encoding the
// decoded entry. Two encodings of the same entry are different leaves.
func TestLeafHashUsesStoredBytes(t *testing.T) {
	canonical, err := NewRefUpdate("refs/heads/main", testObject)
	if err != nil {
		t.Fatal(err)
	}

	// The same entry, semantically, with the keys in a different order and
	// some insignificant whitespace — exactly what a different encoder might
	// produce.
	reordered := []byte(`{"object":"` + testObject + `", "ref":"refs/heads/main", "type":"` + TypeRefUpdate + `"}`)
	other, err := ParseEntry(reordered)
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}

	// Both decode to the same statement...
	a, err := canonical.AsRefUpdate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := other.AsRefUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("expected the same decoded statement, got %+v and %+v", a, b)
	}

	// ...but they are distinct leaves, because the bytes differ. This is why
	// nothing may re-encode an entry to recompute its hash.
	if canonical.LeafHash() == other.LeafHash() {
		t.Error("differently encoded entries must not share a leaf hash")
	}
	if !bytes.Equal(other.Raw(), reordered) {
		t.Error("ParseEntry must preserve the exact bytes it was given")
	}
}

// TestDuplicateKeysRejected covers the parser-divergence hazard: JSON parsers
// disagree about which value wins, so an entry with a repeated key could mean
// different things to two verifiers reading identical bytes.
func TestDuplicateKeysRejected(t *testing.T) {
	line := []byte(`{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","ref":"refs/heads/evil","object":"` + testObject + `"}`)

	// Confirm the hazard is real for a mainstream parser before asserting we
	// reject it: encoding/json silently takes the last value.
	var loose map[string]any
	if err := json.Unmarshal(line, &loose); err != nil {
		t.Fatal(err)
	}
	if loose["ref"] != "refs/heads/evil" {
		t.Fatalf("expected the lenient parse to take the last value, got %v", loose["ref"])
	}

	if _, err := ParseEntry(line); err == nil {
		t.Error("expected a duplicate key to be rejected")
	} else if !strings.Contains(err.Error(), "duplicate key") {
		t.Errorf("expected a duplicate-key diagnostic, got %v", err)
	}
}

func TestParseEntryRejectsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"empty", ``},
		{"not an object", `"just a string"`},
		{"array", `[{"type":"x"}]`},
		{"trailing content", `{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","object":"` + testObject + `"} {}`},
		{"missing type", `{"ref":"refs/heads/main","object":"` + testObject + `"}`},
		{"empty type", `{"type":"","ref":"refs/heads/main"}`},
		{"type not a string", `{"type":123}`},
		{"truncated", `{"type":"` + TypeRefUpdate + `"`},
		{"nested duplicate key", `{"type":"other/v1","x":{"a":1,"a":2}}`},
	} {
		if _, err := ParseEntry([]byte(tc.line)); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

// TestKnownTypeValidatedOnParse checks that a recognised type is checked when
// the log is read, not when some later caller happens to look at it.
func TestKnownTypeValidatedOnParse(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"unknown field", `{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","object":"` + testObject + `","extra":1}`},
		{"bad ref namespace", `{"type":"` + TypeRefUpdate + `","ref":"refs/notes/x","object":"` + testObject + `"}`},
		{"short object", `{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","object":"abcd"}`},
		{"non-hex object", `{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","object":"zzzz30afb02b71590f0b2e0a67f0b846715e1d04"}`},
		{"missing ref", `{"type":"` + TypeRefUpdate + `","object":"` + testObject + `"}`},
	} {
		if _, err := ParseEntry([]byte(tc.line)); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

// TestUnknownFieldsRejected states the evolution rule: a change in what an
// entry means requires a new type version, because an implementation that
// predates the change must not silently ignore the new field.
func TestUnknownFieldsRejected(t *testing.T) {
	line := []byte(`{"type":"` + TypeRefUpdate + `","ref":"refs/heads/main","object":"` + testObject + `","tombstoned":true}`)
	if _, err := ParseEntry(line); err == nil {
		t.Error("expected an unknown field in a known type to be rejected")
	}
}

// TestUnknownTypesAreCriticalByDefault covers forward compatibility: an entry
// this implementation does not understand must be refused unless it explicitly
// says it is safe to skip.
func TestUnknownTypesAreCriticalByDefault(t *testing.T) {
	future := []byte(`{"type":"git-ratchet/tombstone/v1","commit":"` + testObject + `","reason":"legal"}`)
	e, err := ParseEntry(future)
	if err != nil {
		t.Fatalf("an unknown type must still parse as an envelope: %v", err)
	}
	if e.Known() {
		t.Error("tombstone should not be a known type in this implementation")
	}
	if !e.Critical {
		t.Error("an entry that does not mention criticality must default to critical")
	}

	optional := []byte(`{"type":"git-ratchet/annotation/v1","critical":false,"note":"hello"}`)
	o, err := ParseEntry(optional)
	if err != nil {
		t.Fatal(err)
	}
	if o.Critical {
		t.Error(`"critical":false must be honoured`)
	}
}

func TestAsRefUpdateRejectsOtherTypes(t *testing.T) {
	e, err := ParseEntry([]byte(`{"type":"git-ratchet/tombstone/v1","commit":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AsRefUpdate(); err == nil {
		t.Error("expected AsRefUpdate to refuse a different type")
	}
}

func TestNewRefUpdateValidates(t *testing.T) {
	for _, tc := range []struct{ name, ref, object string }{
		{"bad namespace", "refs/notes/x", testObject},
		{"empty ref", "", testObject},
		{"short object", "refs/heads/main", "abcd"},
		{"non-hex object", "refs/heads/main", strings.Repeat("z", 40)},
	} {
		if _, err := NewRefUpdate(tc.ref, tc.object); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
	// SHA-256 repositories use 64-character hashes.
	if _, err := NewRefUpdate("refs/heads/main", strings.Repeat("a", 64)); err != nil {
		t.Errorf("a SHA-256 object hash should be accepted: %v", err)
	}
}
