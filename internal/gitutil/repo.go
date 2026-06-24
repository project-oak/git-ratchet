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

// Package gitutil provides helpers for interacting with a Git repository via
// the git CLI.
package gitutil

import (
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

// ResolveRef resolves a Git reference to a full commit hash.
func ResolveRef(repoDir, ref string) (string, error) {
	out, err := git(repoDir, "rev-parse", ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	return strings.TrimSpace(out), nil
}

// RemoteURL returns the fetch URL of the "origin" remote.
func RemoteURL(repoDir string) (string, error) {
	out, err := git(repoDir, "remote", "get-url", "origin")
	if err != nil {
		return "", fmt.Errorf("getting remote URL: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// checkpointRef converts a source ref like "refs/heads/main" or
// "refs/tags/v1.0" to its checkpoint storage ref, e.g.
// "refs/checkpoints/heads/main" or "refs/checkpoints/tags/v1.0".
func checkpointRef(sourceRef string) string {
	return "refs/checkpoints/" + strings.TrimPrefix(sourceRef, "refs/")
}

// StoreCheckpoint writes a checkpoint string as a Git blob and points
// the corresponding checkpoint ref at it.
// ref must be a full ref path, e.g. "refs/heads/main" or "refs/tags/v1.0".
func StoreCheckpoint(repoDir, ref, checkpoint string) error {
	cmd := exec.Command("git", "-C", repoDir, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(checkpoint)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("writing checkpoint blob: %w", err)
	}
	blobHash := strings.TrimSpace(string(out))

	cpRef := checkpointRef(ref)
	if _, err := git(repoDir, "update-ref", cpRef, blobHash); err != nil {
		return fmt.Errorf("updating ref %s: %w", cpRef, err)
	}
	return nil
}

// ReadCheckpoint reads the checkpoint blob for a ref.
// ref must be a full ref path, e.g. "refs/heads/main" or "refs/tags/v1.0".
func ReadCheckpoint(repoDir, ref string) (string, error) {
	return git(repoDir, "cat-file", "-p", checkpointRef(ref))
}

func git(repoDir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %s: %w", strings.Join(args, " "), strings.TrimSpace(string(out)), err)
	}
	return string(out), nil
}

// IsAncestor reports whether ancestor is an ancestor-or-equal of descendant
// in the repository at repoDir.
//
// Returns (true, nil) when ancestor == descendant or when ancestor is reachable
// by following parent links from descendant. Returns (false, nil) when the
// commit is not an ancestor. Returns a non-nil error only on git failures
// (e.g. unknown commit hash, not a git repository).
func IsAncestor(repoDir, ancestor, descendant string) (bool, error) {
	cmd := exec.Command("git", "-C", repoDir, "merge-base", "--is-ancestor", ancestor, descendant)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Exit code 1 means "not an ancestor" — that is a valid, non-error result.
		if cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("git merge-base --is-ancestor: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return true, nil
}

// GetCommitChain returns a slice of base64-encoded raw Git commit objects
// representing the path from oldCommit to newCommit (excluding oldCommit,
// and including newCommit).
func GetCommitChain(repoDir, oldCommit, newCommit string) ([]string, error) {
	if oldCommit == newCommit {
		return nil, nil
	}

	out, err := git(repoDir, "rev-list", "--reverse", oldCommit+".."+newCommit)
	if err != nil {
		return nil, fmt.Errorf("getting rev-list from %s to %s: %w", oldCommit, newCommit, err)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	var commits []string
	for _, commitHash := range lines {
		commitHash = strings.TrimSpace(commitHash)
		if commitHash == "" {
			continue
		}
		// Get raw commit content.
		content, err := git(repoDir, "cat-file", "-p", commitHash)
		if err != nil {
			return nil, fmt.Errorf("reading commit %s: %w", commitHash, err)
		}
		// Format: "commit <size>\n<content>"
		formatted := fmt.Sprintf("commit %d\n%s", len(content), content)
		commits = append(commits, base64.StdEncoding.EncodeToString([]byte(formatted)))
	}
	return commits, nil
}
