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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Cmd is a git invocation under construction. Start one with [Git]:
//
//	out, err := gitutil.Git(dir).WithEnv("GIT_AUTHOR_NAME=x").Run("commit-tree", tree)
//
// Every git invocation in this package goes through [Cmd.Run].
type Cmd struct {
	repoDir string
	env     []string
	stdin   string
}

// Git starts a git invocation in repoDir.
func Git(repoDir string) *Cmd { return &Cmd{repoDir: repoDir} }

// WithEnv adds environment variables, each "KEY=value", on top of the current
// environment.
func (c *Cmd) WithEnv(env ...string) *Cmd {
	c.env = append(c.env, env...)
	return c
}

// WithStdin supplies the invocation's standard input.
func (c *Cmd) WithStdin(in string) *Cmd {
	c.stdin = in
	return c
}

// Run invokes git and returns its standard output verbatim, so a caller
// reading an object gets the bytes and nothing else. Standard error belongs to
// the error instead, which is an [*ExitError] when git ran and exited non-zero.
//
// Every invocation passes --no-replace-objects. A replace ref substitutes one
// object's content for another's everywhere git reads it, so with them honoured
// a forged stand-in for a logged commit can put an unlogged commit into that
// commit's ancestry, and the ancestry check accepts a ref the log never
// covered. What is checkpointed is the true object graph, so that is the graph
// every read here has to see.
func (c *Cmd) Run(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", c.repoDir, "--no-replace-objects"}, args...)...)
	if len(c.env) > 0 {
		cmd.Env = append(os.Environ(), c.env...)
	}
	if c.stdin != "" {
		cmd.Stdin = strings.NewReader(c.stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			msg := fmt.Sprintf("git %s: exit status %d", strings.Join(args, " "), exit.ExitCode())
			if e := strings.TrimSpace(stderr.String()); e != "" {
				msg = fmt.Sprintf("git %s: %s (exit status %d)", strings.Join(args, " "), e, exit.ExitCode())
			}
			return "", &ExitError{Code: exit.ExitCode(), msg: msg}
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// ExitError reports a git invocation that ran and exited non-zero. Callers
// that treat a particular status as a result rather than a failure, such as
// [IsAncestor], match on it with errors.As and read Code.
type ExitError struct {
	Code int
	msg  string
}

func (e *ExitError) Error() string { return e.msg }

// ResolveRef resolves a Git reference to the hash of the object it points to.
// For branches and lightweight tags this is a commit hash; for annotated tags
// this is the tag object hash (not the underlying commit hash).
func ResolveRef(repoDir, ref string) (string, error) {
	out, err := Git(repoDir).Run("rev-parse", ref)
	if err != nil {
		return "", fmt.Errorf("resolving %s: %w", ref, err)
	}
	return strings.TrimSpace(out), nil
}

// RemoteURL returns the fetch URL of the "origin" remote.
func RemoteURL(repoDir string) (string, error) {
	out, err := Git(repoDir).Run("remote", "get-url", "origin")
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
	blobHash, err := HashObject(repoDir, checkpoint)
	if err != nil {
		return fmt.Errorf("writing checkpoint blob: %w", err)
	}

	cpRef := checkpointRef(ref)
	if _, err := Git(repoDir).Run("update-ref", cpRef, blobHash); err != nil {
		return fmt.Errorf("updating ref %s: %w", cpRef, err)
	}
	return nil
}

// ReadCheckpoint reads the checkpoint blob for a ref.
// ref must be a full ref path, e.g. "refs/heads/main" or "refs/tags/v1.0".
func ReadCheckpoint(repoDir, ref string) (string, error) {
	return Git(repoDir).Run("cat-file", "-p", checkpointRef(ref))
}

// HashObject writes content to the object database as a blob and returns its
// hash.
func HashObject(repoDir, content string) (string, error) {
	out, err := Git(repoDir).WithStdin(content).Run("hash-object", "-w", "--stdin")
	if err != nil {
		return "", fmt.Errorf("writing blob: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// RefExists reports whether a ref is present in the repository.
func RefExists(repoDir, ref string) bool {
	_, err := Git(repoDir).Run("rev-parse", "--verify", "--quiet", ref)
	return err == nil
}

// CatFile returns the contents of an object, addressed by any revision syntax
// git understands (e.g. "refs/ratchet/log:tile/entries/000").
func CatFile(repoDir, object string) (string, error) {
	return Git(repoDir).Run("cat-file", "-p", object)
}

// IsAncestor reports whether ancestor is an ancestor-or-equal of descendant
// in the repository at repoDir.
//
// Returns (true, nil) when ancestor == descendant or when ancestor is reachable
// by following parent links from descendant. Returns (false, nil) when the
// commit is not an ancestor. Returns a non-nil error only on git failures
// (e.g. unknown commit hash, not a git repository).
func IsAncestor(repoDir, ancestor, descendant string) (bool, error) {
	_, err := Git(repoDir).Run("merge-base", "--is-ancestor", ancestor, descendant)
	if err != nil {
		// Exit code 1 means "not an ancestor" — a result, not a failure.
		var exit *ExitError
		if errors.As(err, &exit) && exit.Code == 1 {
			return false, nil
		}
		return false, err
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

	out, err := Git(repoDir).Run("rev-list", "--reverse", oldCommit+".."+newCommit)
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
		content, err := Git(repoDir).Run("cat-file", "-p", commitHash)
		if err != nil {
			return nil, fmt.Errorf("reading commit %s: %w", commitHash, err)
		}
		// Format: "commit <size>\n<content>"
		formatted := fmt.Sprintf("commit %d\n%s", len(content), content)
		commits = append(commits, base64.StdEncoding.EncodeToString([]byte(formatted)))
	}
	return commits, nil
}
