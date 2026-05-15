// Package gitutil provides helpers for interacting with a Git repository via
// the git CLI.
package gitutil

import (
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
