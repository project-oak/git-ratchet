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

package gitutil

import (
	"fmt"
	"strings"
)

// RefKind distinguishes the two kinds of ref that git-ratchet operates on.
type RefKind int

const (
	RefBranch RefKind = iota
	RefTag
)

// ParseRefKind returns the kind of a full ref path (e.g. "refs/heads/main"
// or "refs/tags/v1.0"). It returns an error if the ref does not match
// either "refs/heads/" or "refs/tags/".
func ParseRefKind(ref string) (RefKind, error) {
	switch {
	case strings.HasPrefix(ref, "refs/tags/"):
		return RefTag, nil
	case strings.HasPrefix(ref, "refs/heads/"):
		return RefBranch, nil
	default:
		return 0, fmt.Errorf("unrecognised ref prefix: %q", ref)
	}
}
