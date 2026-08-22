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
	"strings"
	"testing"

	"github.com/transparency-dev/tessera/api"
)

const testObject = "4f0f30afb02b71590f0b2e0a67f0b846715e1d04"

func TestNewRefRecordWireForm(t *testing.T) {
	e, err := NewRefRecord("refs/heads/main", testObject)
	if err != nil {
		t.Fatal(err)
	}
	want := "ref-record/v1\nrefs/heads/main " + testObject + "\n"
	if got := string(e.Raw()); got != want {
		t.Errorf("wire form = %q, want %q", got, want)
	}
	if e.Type != TypeRefRecord {
		t.Errorf("Type = %q", e.Type)
	}
}

func TestRefRecordRoundTrip(t *testing.T) {
	e, err := NewRefRecord("refs/tags/v1.0.0", testObject)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEntry(e.Raw())
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	rr, err := parsed.AsRefRecord()
	if err != nil {
		t.Fatalf("AsRefRecord: %v", err)
	}
	if rr.Ref != "refs/tags/v1.0.0" || rr.Object != testObject {
		t.Errorf("round trip = %+v", rr)
	}
	if parsed.LeafHash() != e.LeafHash() {
		t.Error("leaf hash changed across a parse")
	}
}

// TestEncodingIsCanonical checks that the grammar admits exactly one byte
// string per statement. Anything accepted in a second written form would be a
// place where two encoders produce different leaf hashes for the same thing.
func TestEncodingIsCanonical(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"no trailing newline", "ref-record/v1\nrefs/heads/main " + testObject},
		{"two spaces", "ref-record/v1\nrefs/heads/main  " + testObject + "\n"},
		{"leading space", "ref-record/v1\n refs/heads/main " + testObject + "\n"},
		{"trailing space", "ref-record/v1\nrefs/heads/main " + testObject + " \n"},
		{"carriage return", "ref-record/v1\r\nrefs/heads/main " + testObject + "\n"},
		{"uppercase hex", "ref-record/v1\nrefs/heads/main " + strings.ToUpper(testObject) + "\n"},
		{"extra line", "ref-record/v1\nrefs/heads/main " + testObject + "\nextra\n"},
		{"blank line", "ref-record/v1\n\nrefs/heads/main " + testObject + "\n"},
		{"type line only", "ref-record/v1\n"},
	} {
		if _, err := ParseEntry([]byte(tc.raw)); err == nil {
			t.Errorf("%s: expected rejection, got none", tc.name)
		}
	}
}

func TestParseEntryRejectsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"empty", ""},
		{"empty type", "\nrefs/heads/main " + testObject + "\n"},
		{"type with space", "ref record/v1\nrefs/heads/main " + testObject + "\n"},
		{"bad ref namespace", "ref-record/v1\nrefs/notes/x " + testObject + "\n"},
		{"short object", "ref-record/v1\nrefs/heads/main abcd\n"},
		{"non-hex object", "ref-record/v1\nrefs/heads/main " + strings.Repeat("z", 40) + "\n"},
		{"missing object", "ref-record/v1\nrefs/heads/main\n"},
	} {
		if _, err := ParseEntry([]byte(tc.raw)); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}

// TestUnknownTypeKeepsBytes checks that an entry of an unrecognised type still
// parses and keeps its bytes, so it contributes the right leaf to the tree
// even though its meaning is unavailable.
func TestUnknownTypeKeepsBytes(t *testing.T) {
	raw := "tombstone/v1\n" + testObject + " refs/heads/main\na reason\n\nwith a blank line\n"
	e, err := ParseEntry([]byte(raw))
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if e.Type != "tombstone/v1" {
		t.Errorf("Type = %q", e.Type)
	}
	if e.Known() {
		t.Error("tombstone should not be known")
	}
	if string(e.Raw()) != raw {
		t.Error("ParseEntry must preserve the exact bytes it was given")
	}
	if _, err := e.AsRefRecord(); err == nil {
		t.Error("AsRefRecord should refuse a different type")
	}
}

func TestNewRefRecordValidates(t *testing.T) {
	for _, tc := range []struct{ name, ref, object string }{
		{"bad namespace", "refs/notes/x", testObject},
		{"empty ref", "", testObject},
		{"short object", "refs/heads/main", "abcd"},
		{"uppercase object", "refs/heads/main", strings.ToUpper(testObject)},
		{"non-hex object", "refs/heads/main", strings.Repeat("z", 40)},
	} {
		if _, err := NewRefRecord(tc.ref, tc.object); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
	// SHA-256 repositories use 64-character hashes.
	if _, err := NewRefRecord("refs/heads/main", strings.Repeat("a", 64)); err != nil {
		t.Errorf("a SHA-256 object hash should be accepted: %v", err)
	}
}

// TestBundleEncodingMatchesReference pins our writer against the tlog-tiles
// reference decoder. Writing bundles in a format only we could read is the
// defect this test exists to prevent.
func TestBundleEncodingMatchesReference(t *testing.T) {
	entries := []Entry{
		mustRefRecord(t, "refs/heads/main", obj("aaaa")),
		mustRefRecord(t, "refs/tags/v1.0.0", obj("bbbb")),
	}
	// An entry containing newlines and a blank line, which the length-prefixed
	// framing must carry without any escaping.
	awkward, err := ParseEntry([]byte("tombstone/v1\n" + testObject + " refs/heads/main\nline one\n\nline two\n"))
	if err != nil {
		t.Fatal(err)
	}
	entries = append(entries, awkward)

	raw, err := marshalBundle(entries)
	if err != nil {
		t.Fatalf("marshalBundle: %v", err)
	}

	var bundle api.EntryBundle
	if err := bundle.UnmarshalText(raw); err != nil {
		t.Fatalf("the reference decoder rejected our bundle: %v", err)
	}
	if len(bundle.Entries) != len(entries) {
		t.Fatalf("decoded %d entries, want %d", len(bundle.Entries), len(entries))
	}
	for i := range entries {
		if string(bundle.Entries[i]) != string(entries[i].Raw()) {
			t.Errorf("entry %d did not survive the round trip:\ngot  %q\nwant %q",
				i, bundle.Entries[i], entries[i].Raw())
		}
	}
}

func TestMarshalBundleRejectsOversizedEntry(t *testing.T) {
	// Construct an entry larger than a uint16 length prefix can describe.
	big := Entry{raw: []byte("x/v1\n" + strings.Repeat("a", MaxEntrySize) + "\n"), Type: "x/v1"}
	if _, err := marshalBundle([]Entry{big}); err == nil {
		t.Error("expected an oversized entry to be rejected")
	}
}
