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
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
	"strings"
)

// CommitHash computes the Git object hash for a raw commit object.
// decoded must have the form "commit <size>\n<content>" where size equals
// len(content).  The hash algorithm is selected by the length of the expected
// commit ID: 64 hex chars → SHA-256 (git >= 2.29 with sha256 object format),
// anything else → SHA-1.
//
// This function is used both by the witness server (to verify ancestry proofs)
// and by test helpers that need to reproduce Git's object-ID computation.
func CommitHash(decoded []byte, expectedHashLen int) (string, error) {
	s := string(decoded)
	if !strings.HasPrefix(s, "commit ") {
		return "", fmt.Errorf("invalid commit prefix")
	}
	idx := strings.IndexByte(s, '\n')
	if idx < 0 {
		return "", fmt.Errorf("invalid format: missing newline after header")
	}
	header := s[:idx]
	content := s[idx+1:]

	var size int
	if _, err := fmt.Sscanf(header, "commit %d", &size); err != nil {
		return "", fmt.Errorf("parsing size: %w", err)
	}
	if size != len(content) {
		return "", fmt.Errorf("size mismatch: header says %d, actual %d", size, len(content))
	}

	var h hash.Hash
	if expectedHashLen == 64 {
		h = sha256.New()
	} else {
		h = sha1.New()
	}
	h.Write([]byte(fmt.Sprintf("commit %d\x00", size)))
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
