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
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Checkpoint is the body of a C2SP tlog-checkpoint: the log's origin, the size
// of the tree, and its root hash.
//
// Unlike git-ratchet's git-checkpoint body, this format carries no Git-specific
// fields, so any conforming tlog witness can parse and cosign it.
type Checkpoint struct {
	Origin string
	Size   int
	Root   Hash

	// Extensions holds any additional body lines after the root hash. They are
	// preserved so that signature verification round-trips exactly.
	Extensions []string
}

// Body renders the checkpoint body, terminated by a newline. This is the exact
// byte sequence the origin signs and witnesses cosign.
//
//	<origin>\n
//	<size>\n
//	<base64 root hash>\n
func (c Checkpoint) Body() string {
	var b strings.Builder
	b.WriteString(c.Origin)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(c.Size))
	b.WriteByte('\n')
	b.WriteString(base64.StdEncoding.EncodeToString(c.Root[:]))
	b.WriteByte('\n')
	for _, ext := range c.Extensions {
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	return b.String()
}

// ParseCheckpoint parses a tlog-checkpoint body.
func ParseCheckpoint(body string) (Checkpoint, error) {
	var cp Checkpoint

	// The body is newline-terminated; drop the trailing empty field.
	lines := strings.Split(body, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		return cp, fmt.Errorf("malformed tlog checkpoint: need at least 3 lines, got %d", len(lines))
	}

	cp.Origin = lines[0]
	if cp.Origin == "" {
		return cp, fmt.Errorf("malformed tlog checkpoint: empty origin")
	}

	size, err := strconv.Atoi(lines[1])
	if err != nil {
		return cp, fmt.Errorf("malformed tlog checkpoint: invalid size %q", lines[1])
	}
	if size < 0 {
		return cp, fmt.Errorf("malformed tlog checkpoint: negative size %d", size)
	}
	cp.Size = size

	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return cp, fmt.Errorf("malformed tlog checkpoint: invalid root hash encoding: %w", err)
	}
	if len(root) != HashSize {
		return cp, fmt.Errorf("malformed tlog checkpoint: root hash is %d bytes, want %d", len(root), HashSize)
	}
	copy(cp.Root[:], root)

	if len(lines) > 3 {
		cp.Extensions = lines[3:]
	}
	return cp, nil
}
