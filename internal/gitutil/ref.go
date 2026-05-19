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
