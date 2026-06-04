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
	"testing"
)

// gitObjectHash computes the git object hash for a commit with the given
// content, using SHA-1 or SHA-256 depending on sha256Mode.
func gitObjectHash(content string, sha256Mode bool) string {
	if sha256Mode {
		h := sha256.New()
		fmt.Fprintf(h, "commit %d\x00", len(content))
		h.Write([]byte(content))
		return fmt.Sprintf("%x", h.Sum(nil))
	}
	h := sha1.New()
	fmt.Fprintf(h, "commit %d\x00", len(content))
	h.Write([]byte(content))
	return fmt.Sprintf("%x", h.Sum(nil))
}

const testCommitContent = "tree 0000000000000000000000000000000000000001\nauthor Test <t@t.com> 1000000000 +0000\ncommitter Test <t@t.com> 1000000000 +0000\n\ntest commit\n"

func TestCommitHashSHA1(t *testing.T) {
	wireBytes := []byte(fmt.Sprintf("commit %d\n%s", len(testCommitContent), testCommitContent))
	want := gitObjectHash(testCommitContent, false)

	got, err := CommitHash(wireBytes, sha1.Size*2) // 40 hex chars
	if err != nil {
		t.Fatalf("CommitHash returned error: %v", err)
	}
	if got != want {
		t.Errorf("SHA-1 hash mismatch: got %s, want %s", got, want)
	}
	if len(got) != 40 {
		t.Errorf("SHA-1 hash should be 40 hex chars, got %d", len(got))
	}
}

func TestCommitHashSHA256(t *testing.T) {
	wireBytes := []byte(fmt.Sprintf("commit %d\n%s", len(testCommitContent), testCommitContent))
	want := gitObjectHash(testCommitContent, true)

	got, err := CommitHash(wireBytes, sha256.Size*2) // 64 hex chars
	if err != nil {
		t.Fatalf("CommitHash returned error: %v", err)
	}
	if got != want {
		t.Errorf("SHA-256 hash mismatch: got %s, want %s", got, want)
	}
	if len(got) != 64 {
		t.Errorf("SHA-256 hash should be 64 hex chars, got %d", len(got))
	}
}

func TestCommitHashSameInputDifferentAlgorithm(t *testing.T) {
	wireBytes := []byte(fmt.Sprintf("commit %d\n%s", len(testCommitContent), testCommitContent))

	sha1Hash, err := CommitHash(wireBytes, 40)
	if err != nil {
		t.Fatalf("SHA-1 CommitHash error: %v", err)
	}
	sha256Hash, err := CommitHash(wireBytes, 64)
	if err != nil {
		t.Fatalf("SHA-256 CommitHash error: %v", err)
	}

	if sha1Hash == sha256Hash {
		t.Error("SHA-1 and SHA-256 hashes should differ for the same input")
	}
	if len(sha1Hash) != 40 {
		t.Errorf("SHA-1 hash length: got %d, want 40", len(sha1Hash))
	}
	if len(sha256Hash) != 64 {
		t.Errorf("SHA-256 hash length: got %d, want 64", len(sha256Hash))
	}
}

func TestCommitHashInvalidPrefix(t *testing.T) {
	_, err := CommitHash([]byte("blob 5\nhello"), 40)
	if err == nil {
		t.Error("expected error for non-commit prefix")
	}
}

func TestCommitHashSizeMismatch(t *testing.T) {
	// Header says 10 but actual content is shorter.
	_, err := CommitHash([]byte("commit 10\nshort"), 40)
	if err == nil {
		t.Error("expected error for size mismatch")
	}
}

func TestCommitHashMissingNewline(t *testing.T) {
	_, err := CommitHash([]byte("commit 5"), 40)
	if err == nil {
		t.Error("expected error for missing newline")
	}
}

func TestCommitHashWithParent(t *testing.T) {
	// Test a commit with a parent field, using both hash lengths for the parent.
	for _, tc := range []struct {
		name       string
		parentLen  int
		expectLen  int
		sha256Mode bool
	}{
		{"SHA-1 parent in SHA-1 commit", 40, 40, false},
		{"SHA-256 parent in SHA-256 commit", 64, 64, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := make([]byte, tc.parentLen)
			for i := range parent {
				parent[i] = 'a'
			}
			content := fmt.Sprintf("tree %s\nparent %s\nauthor Test <t@t.com> 1000000000 +0000\ncommitter Test <t@t.com> 1000000000 +0000\n\nchild commit\n",
				string(make([]byte, tc.parentLen)), // tree hash (same length)
				string(parent))
			wireBytes := []byte(fmt.Sprintf("commit %d\n%s", len(content), content))

			got, err := CommitHash(wireBytes, tc.expectLen)
			if err != nil {
				t.Fatalf("CommitHash error: %v", err)
			}
			if len(got) != tc.expectLen {
				t.Errorf("hash length: got %d, want %d", len(got), tc.expectLen)
			}

			want := gitObjectHash(content, tc.sha256Mode)
			if got != want {
				t.Errorf("hash mismatch: got %s, want %s", got, want)
			}
		})
	}
}
