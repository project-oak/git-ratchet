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

package tlog

import (
	"strings"
	"testing"
)

func TestCheckpointBodyFormat(t *testing.T) {
	cp := Checkpoint{
		Origin: "github.com/example/repo",
		Size:   42,
		Root:   HashLeaf([]byte("x")),
	}
	body := cp.Body()

	lines := strings.Split(body, "\n")
	if len(lines) != 4 || lines[3] != "" {
		t.Fatalf("body should be three newline-terminated lines, got %q", body)
	}
	if lines[0] != "github.com/example/repo" {
		t.Errorf("origin line = %q", lines[0])
	}
	if lines[1] != "42" {
		t.Errorf("size line = %q", lines[1])
	}
}

func TestCheckpointRoundTrip(t *testing.T) {
	want := Checkpoint{
		Origin: "github.com/example/repo",
		Size:   1234,
		Root:   HashLeaf([]byte("root")),
	}
	got, err := ParseCheckpoint(want.Body())
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	if got.Origin != want.Origin || got.Size != want.Size || got.Root != want.Root {
		t.Errorf("round trip mismatch: got %+v, want %+v", got, want)
	}
}

// TestCheckpointExtensionsRoundTrip checks that unknown trailing lines survive
// parsing and re-rendering, so signatures over the body still verify.
func TestCheckpointExtensionsRoundTrip(t *testing.T) {
	body := "example.com/log\n7\n" +
		"3q2+7w6rvu8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n" +
		"custom extension line\n"
	cp, err := ParseCheckpoint(body)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	if len(cp.Extensions) != 1 || cp.Extensions[0] != "custom extension line" {
		t.Fatalf("extensions = %q", cp.Extensions)
	}
	if cp.Body() != body {
		t.Errorf("body did not round trip:\ngot  %q\nwant %q", cp.Body(), body)
	}
}

func TestParseCheckpointErrors(t *testing.T) {
	valid := Checkpoint{Origin: "o", Size: 1, Root: HashLeaf(nil)}.Body()

	for _, tc := range []struct{ name, body string }{
		{"too short", "example.com/log\n5\n"},
		{"empty origin", "\n5\nAAAA\n"},
		{"non-numeric size", "example.com/log\nmany\n" + strings.SplitN(valid, "\n", 3)[2]},
		{"negative size", "example.com/log\n-1\n" + strings.SplitN(valid, "\n", 3)[2]},
		{"bad base64", "example.com/log\n5\nnot!base64\n"},
		{"short root hash", "example.com/log\n5\nAAAA\n"},
		{"empty", ""},
	} {
		if _, err := ParseCheckpoint(tc.body); err == nil {
			t.Errorf("%s: expected an error, got none", tc.name)
		}
	}
}
