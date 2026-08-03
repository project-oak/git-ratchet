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

package witness

import (
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

func TestTlogRequestRoundTrip(t *testing.T) {
	proof := []tlog.Hash{
		tlog.HashLeaf([]byte("a")),
		tlog.HashLeaf([]byte("b")),
	}
	signedNote := "example.com/log\n7\nAAAA\n\n— origin+abcd1234 sig\n"

	body := FormatTlogRequest(5, proof, signedNote)
	req, err := ParseTlogRequest(body)
	if err != nil {
		t.Fatalf("ParseTlogRequest: %v", err)
	}
	if req.OldSize != 5 {
		t.Errorf("OldSize = %d, want 5", req.OldSize)
	}
	if len(req.Proof) != 2 || req.Proof[0] != proof[0] || req.Proof[1] != proof[1] {
		t.Errorf("Proof = %v", req.Proof)
	}
	if req.Note != signedNote {
		t.Errorf("Note = %q, want %q", req.Note, signedNote)
	}
}

// TestTlogRequestEmptyProof covers the first-submission case, where the client
// has nothing to prove because the witness has no stored state.
func TestTlogRequestEmptyProof(t *testing.T) {
	signedNote := "example.com/log\n1\nAAAA\n\n— origin+abcd1234 sig\n"
	req, err := ParseTlogRequest(FormatTlogRequest(0, nil, signedNote))
	if err != nil {
		t.Fatalf("ParseTlogRequest: %v", err)
	}
	if req.OldSize != 0 {
		t.Errorf("OldSize = %d, want 0", req.OldSize)
	}
	if len(req.Proof) != 0 {
		t.Errorf("Proof = %v, want empty", req.Proof)
	}
}

func TestParseTlogRequestErrors(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"no old line", "\n\nnote\n"},
		{"bad old size", "old xyz\n\nnote\n"},
		{"negative old size", "old -1\n\nnote\n"},
		{"no separator", "old 1\n" + strings.Repeat("A", 44) + "\n"},
		{"bad base64 proof", "old 1\nnot!base64\n\nnote\n"},
		{"short proof hash", "old 1\nAAAA\n\nnote\n"},
		{"empty note", "old 1\n\n\n"},
	} {
		if _, err := ParseTlogRequest(tc.body); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}
