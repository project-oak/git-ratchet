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

// StoreCheckpoint writes a checkpoint string as a Git blob and points
// refs/checkpoints/<branch> at it.
func StoreCheckpoint(repoDir, branch, checkpoint string) error {
	cmd := exec.Command("git", "-C", repoDir, "hash-object", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(checkpoint)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("writing checkpoint blob: %w", err)
	}
	blobHash := strings.TrimSpace(string(out))

	ref := "refs/checkpoints/" + branch
	if _, err := git(repoDir, "update-ref", ref, blobHash); err != nil {
		return fmt.Errorf("updating ref %s: %w", ref, err)
	}
	return nil
}

// ReadCheckpoint reads the checkpoint blob for a branch.
func ReadCheckpoint(repoDir, branch string) (string, error) {
	ref := "refs/checkpoints/" + branch
	return git(repoDir, "cat-file", "-p", ref)
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
