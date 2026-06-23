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
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/project-oak/git-ratchet/internal/gitutil"
)

// ParseAddCheckpointRequest splits an add-checkpoint request body into the
// ancestry proof lines and the signed note. The format is:
//
//	<base64-commit-object>\n
//	...\n
//	\n           ← empty line separator
//	<signed note>
//
// The ancestry section may be empty (the empty line separator is still required).
func ParseAddCheckpointRequest(body string) (ancestry []string, signedNote string, err error) {
	lines := strings.Split(body, "\n")
	emptyLineIdx := -1
	for i, line := range lines {
		if line == "" {
			emptyLineIdx = i
			break
		}
		ancestry = append(ancestry, line)
	}
	if emptyLineIdx < 0 {
		return nil, "", fmt.Errorf("malformed request: missing empty line separator")
	}
	signedNote = strings.Join(lines[emptyLineIdx+1:], "\n")
	if strings.TrimSpace(signedNote) == "" {
		return nil, "", fmt.Errorf("malformed request: empty signed note")
	}
	return ancestry, signedNote, nil
}

// ParseCheckpointBody extracts the origin, ref, and commit hash from a
// checkpoint note body. The expected format is:
//
//	<origin> <ref>\n
//	<commit-hash>\n
func ParseCheckpointBody(noteBody string) (origin string, ref string, commit string, err error) {
	bodyLines := strings.Split(strings.TrimSpace(noteBody), "\n")
	if len(bodyLines) < 2 {
		return "", "", "", fmt.Errorf("malformed checkpoint body: need at least 2 lines, got %d", len(bodyLines))
	}
	refParts := strings.Fields(bodyLines[0])
	if len(refParts) != 2 {
		return "", "", "", fmt.Errorf("malformed ref line in checkpoint body: expected 2 fields, got %d", len(refParts))
	}
	origin = refParts[0]
	ref = refParts[1]
	commit = strings.TrimSpace(bodyLines[1])
	return origin, ref, commit, nil
}

// VerifyAncestry checks that newCommit descends from storedCommit by walking
// the provided ancestry proof using BFS. Each element of ancestry is a
// base64-encoded Git commit object (wire format: "commit <size>\n<content>").
// hashLen is the length of the hex commit IDs (40 for SHA-1, 64 for SHA-256).
func VerifyAncestry(ancestry []string, storedCommit, newCommit string, hashLen int) error {
	commitMap := make(map[string]string)
	for _, b64Obj := range ancestry {
		decoded, err := base64.StdEncoding.DecodeString(b64Obj)
		if err != nil {
			return fmt.Errorf("malformed base64 encoding in ancestry proof")
		}
		commitID, err := gitutil.CommitHash(decoded, hashLen)
		if err != nil {
			return fmt.Errorf("invalid commit object in ancestry proof: %v", err)
		}
		s := string(decoded)
		idx := strings.IndexByte(s, '\n')
		if idx >= 0 {
			commitMap[commitID] = s[idx+1:]
		}
	}

	// Traverse ancestry DAG backward from newCommit to storedCommit.
	queue := []string{newCommit}
	visited := map[string]bool{newCommit: true}
	found := false

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr == storedCommit {
			found = true
			break
		}

		content, ok := commitMap[curr]
		if !ok {
			continue
		}

		parents := ParseParents(content)
		for _, p := range parents {
			if !visited[p] {
				visited[p] = true
				queue = append(queue, p)
			}
		}
	}

	if !found {
		return fmt.Errorf("ancestry verification failed: new commit does not descend from stored commit")
	}
	return nil
}

// ParseParents extracts parent commit hashes from a Git commit object's content
// (the portion after the "commit <size>\n" header).
func ParseParents(content string) []string {
	var parents []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "parent ") {
			parents = append(parents, strings.TrimPrefix(line, "parent "))
		}
	}
	return parents
}
