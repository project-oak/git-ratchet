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
	"fmt"
	"strconv"
	"strings"
)

// entriesPrefix is the tlog-tiles directory holding entry bundles.
const entriesPrefix = "tile/entries/"

// bundlePath returns the path of entry bundle n holding width entries.
//
// The index is encoded in the tlog-tiles style: base-1000 groups of three
// digits, joined by "/", with every group but the last prefixed by "x". A
// bundle that is not yet full carries a ".p/<width>" suffix, so a partial
// bundle never occupies the path its eventual full form will take.
func bundlePath(n, width int) string {
	path := entriesPrefix + encodeTileIndex(n)
	if width < EntriesPerBundle {
		path += ".p/" + strconv.Itoa(width)
	}
	return path
}

func encodeTileIndex(n int) string {
	// Split into base-1000 groups, most significant first.
	var groups []int
	for {
		groups = append([]int{n % 1000}, groups...)
		n /= 1000
		if n == 0 {
			break
		}
	}

	var b strings.Builder
	for i, g := range groups {
		if i > 0 {
			b.WriteByte('/')
		}
		if i < len(groups)-1 {
			b.WriteByte('x')
		}
		fmt.Fprintf(&b, "%03d", g)
	}
	return b.String()
}

// parseBundlePath recovers the bundle index from a path produced by
// bundlePath. The width suffix is not returned: how many entries a bundle
// holds is evident from its contents, and trusting the path would let a
// malformed tree disagree with itself.
func parseBundlePath(path string) (int, error) {
	rest, ok := strings.CutPrefix(path, entriesPrefix)
	if !ok {
		return 0, fmt.Errorf("path %q is not an entry bundle", path)
	}

	// Drop a ".p/<width>" suffix if present.
	if i := strings.Index(rest, ".p/"); i >= 0 {
		width := rest[i+len(".p/"):]
		if _, err := strconv.Atoi(width); err != nil {
			return 0, fmt.Errorf("path %q has a malformed partial-bundle width %q", path, width)
		}
		rest = rest[:i]
	}

	groups := strings.Split(rest, "/")
	n := 0
	for i, g := range groups {
		if i < len(groups)-1 {
			var ok bool
			g, ok = strings.CutPrefix(g, "x")
			if !ok {
				return 0, fmt.Errorf("path %q has an unprefixed intermediate group", path)
			}
		} else if strings.HasPrefix(g, "x") {
			return 0, fmt.Errorf("path %q has a prefixed final group", path)
		}
		if len(g) != 3 {
			return 0, fmt.Errorf("path %q has a group that is not three digits: %q", path, g)
		}
		v, err := strconv.Atoi(g)
		if err != nil {
			return 0, fmt.Errorf("path %q has a non-numeric group %q", path, g)
		}
		n = n*1000 + v
	}
	return n, nil
}
