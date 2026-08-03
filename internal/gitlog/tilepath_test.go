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

import "testing"

func TestBundlePath(t *testing.T) {
	for _, tc := range []struct {
		n, width int
		want     string
	}{
		{0, EntriesPerBundle, "tile/entries/000"},
		{0, 7, "tile/entries/000.p/7"},
		{1, EntriesPerBundle, "tile/entries/001"},
		{999, EntriesPerBundle, "tile/entries/999"},
		{1000, EntriesPerBundle, "tile/entries/x001/000"},
		{1234567, EntriesPerBundle, "tile/entries/x001/x234/567"},
		{1234567, 3, "tile/entries/x001/x234/567.p/3"},
	} {
		if got := bundlePath(tc.n, tc.width); got != tc.want {
			t.Errorf("bundlePath(%d, %d) = %q, want %q", tc.n, tc.width, got, tc.want)
		}
	}
}

func TestParseBundlePathRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 42, 999, 1000, 1001, 999999, 1000000, 1234567} {
		for _, width := range []int{EntriesPerBundle, 1, 255} {
			path := bundlePath(n, width)
			got, err := parseBundlePath(path)
			if err != nil {
				t.Fatalf("parseBundlePath(%q): %v", path, err)
			}
			if got != n {
				t.Errorf("parseBundlePath(%q) = %d, want %d", path, got, n)
			}
		}
	}
}

func TestParseBundlePathErrors(t *testing.T) {
	for _, bad := range []string{
		"checkpoint",
		"tile/0/000",
		"tile/entries/1",
		"tile/entries/0000",
		"tile/entries/001/002",
		"tile/entries/x001",
		"tile/entries/abc",
		"tile/entries/000.p/x",
	} {
		if _, err := parseBundlePath(bad); err == nil {
			t.Errorf("parseBundlePath(%q): expected an error", bad)
		}
	}
}
