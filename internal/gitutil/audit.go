package gitutil

import (
	"fmt"
	"os/exec"
	"strings"
)

// Fsck runs "git fsck --no-progress" on the repository and returns a non-nil
// error if the object database is inconsistent (hash mismatches, missing
// objects, malformed DAG structure, etc.).
func Fsck(repoDir string) error {
	cmd := exec.Command("git", "-C", repoDir, "fsck", "--no-progress")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git fsck: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ListReplaceRefs returns all refs under refs/replace/. An empty slice means
// no replace refs exist.
func ListReplaceRefs(repoDir string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoDir, "for-each-ref", "--format=%(refname)", "refs/replace/")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("listing replace refs: %s: %w", strings.TrimSpace(string(out)), err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, nil
	}
	return strings.Split(trimmed, "\n"), nil
}
