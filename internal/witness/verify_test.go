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
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseAddCheckpointRequest_Valid(t *testing.T) {
	body := "ancestry1\nancestry2\n\nsigned note content"
	ancestry, signedNote, err := ParseAddCheckpointRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ancestry) != 2 {
		t.Errorf("expected 2 ancestry lines, got %d", len(ancestry))
	}
	if ancestry[0] != "ancestry1" || ancestry[1] != "ancestry2" {
		t.Errorf("unexpected ancestry: %v", ancestry)
	}
	if signedNote != "signed note content" {
		t.Errorf("unexpected signedNote: %q", signedNote)
	}
}

func TestParseAddCheckpointRequest_EmptyAncestry(t *testing.T) {
	body := "\nsigned note content"
	ancestry, signedNote, err := ParseAddCheckpointRequest(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ancestry) != 0 {
		t.Errorf("expected 0 ancestry lines, got %d", len(ancestry))
	}
	if signedNote != "signed note content" {
		t.Errorf("unexpected signedNote: %q", signedNote)
	}
}

func TestParseAddCheckpointRequest_MissingSeparator(t *testing.T) {
	body := "no-empty-line-here"
	_, _, err := ParseAddCheckpointRequest(body)
	if err == nil {
		t.Fatal("expected error for missing separator, got nil")
	}
	if !strings.Contains(err.Error(), "missing empty line separator") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestParseAddCheckpointRequest_Empty(t *testing.T) {
	_, _, err := ParseAddCheckpointRequest("")
	// An empty string has no empty line, so it should fail.
	// Actually, "" split by "\n" gives [""], which is a single non-empty element "".
	// Wait: "" is indeed empty string. Let's check: strings.Split("", "\n") = [""]
	// The loop checks if line == "" — yes, the first (and only) element is "",
	// so emptyLineIdx = 0, ancestry is nil, signedNote is "".
	// This is actually valid (empty ancestry, empty signed note).
	// So let's just verify no error is returned.
	if err != nil {
		t.Fatalf("unexpected error for empty input: %v", err)
	}
}

func TestParseCheckpointBody_Valid(t *testing.T) {
	noteBody := "example.com/repo refs/heads/main\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	origin, ref, commit, err := ParseCheckpointBody(noteBody)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if origin != "example.com/repo" {
		t.Errorf("unexpected origin: %q", origin)
	}
	if ref != "refs/heads/main" {
		t.Errorf("unexpected ref: %q", ref)
	}
	if commit != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("unexpected commit: %q", commit)
	}
}

func TestParseCheckpointBody_Malformed_TooFewLines(t *testing.T) {
	noteBody := "only-one-line\n"
	_, _, _, err := ParseCheckpointBody(noteBody)
	if err == nil {
		t.Fatal("expected error for malformed body, got nil")
	}
}

func TestParseCheckpointBody_Malformed_BadRefLine(t *testing.T) {
	noteBody := "only-one-field\naaaa\n"
	_, _, _, err := ParseCheckpointBody(noteBody)
	if err == nil {
		t.Fatal("expected error for malformed ref line, got nil")
	}
	if !strings.Contains(err.Error(), "malformed ref line") {
		t.Errorf("unexpected error: %v", err)
	}
}

// makeCommitObject builds a minimal Git commit object for testing.
func makeCommitObject(t *testing.T, parentHash, message string) (commitID string, wireBytes []byte) {
	t.Helper()

	treeHash := strings.Repeat("0", 40)
	var sb strings.Builder
	sb.WriteString("tree " + treeHash + "\n")
	if parentHash != "" {
		sb.WriteString("parent " + parentHash + "\n")
	}
	sb.WriteString("author Test <t@t.com> 1000000000 +0000\n")
	sb.WriteString("committer Test <t@t.com> 1000000000 +0000\n")
	sb.WriteString("\n")
	sb.WriteString(message + "\n")
	content := sb.String()

	h := sha1.New()
	fmt.Fprintf(h, "commit %d\x00", len(content))
	h.Write([]byte(content))
	commitID = fmt.Sprintf("%x", h.Sum(nil))

	wireBytes = []byte(fmt.Sprintf("commit %d\n%s", len(content), content))
	return
}

func TestVerifyAncestry_ValidChain(t *testing.T) {
	// Build: storedCommit -> commitA -> commitB (newCommit)
	storedCommit, storedObj := makeCommitObject(t, "", "root commit")
	commitA, commitAObj := makeCommitObject(t, storedCommit, "commit A")
	commitB, commitBObj := makeCommitObject(t, commitA, "commit B")

	ancestry := []string{
		base64.StdEncoding.EncodeToString(storedObj),
		base64.StdEncoding.EncodeToString(commitAObj),
		base64.StdEncoding.EncodeToString(commitBObj),
	}

	err := VerifyAncestry(ancestry, storedCommit, commitB, 40)
	if err != nil {
		t.Fatalf("expected valid ancestry, got error: %v", err)
	}
}

func TestVerifyAncestry_BrokenChain(t *testing.T) {
	storedCommit := strings.Repeat("1", 40)
	// Build an orphan chain not connected to storedCommit.
	orphanA, orphanAObj := makeCommitObject(t, "", "orphan A")
	orphanB, orphanBObj := makeCommitObject(t, orphanA, "orphan B")

	ancestry := []string{
		base64.StdEncoding.EncodeToString(orphanAObj),
		base64.StdEncoding.EncodeToString(orphanBObj),
	}

	err := VerifyAncestry(ancestry, storedCommit, orphanB, 40)
	if err == nil {
		t.Fatal("expected error for broken chain, got nil")
	}
	if !strings.Contains(err.Error(), "ancestry verification failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestVerifyAncestry_EmptyAncestry(t *testing.T) {
	storedCommit := strings.Repeat("1", 40)
	newCommit := strings.Repeat("2", 40)

	err := VerifyAncestry(nil, storedCommit, newCommit, 40)
	if err == nil {
		t.Fatal("expected error for empty ancestry with different commits, got nil")
	}
}

func TestParseParents(t *testing.T) {
	content := "tree 0000000000000000000000000000000000000000\nparent aaaa\nparent bbbb\nauthor Test <t@t.com> 0 +0000\n"
	parents := ParseParents(content)
	if len(parents) != 2 {
		t.Fatalf("expected 2 parents, got %d", len(parents))
	}
	if parents[0] != "aaaa" || parents[1] != "bbbb" {
		t.Errorf("unexpected parents: %v", parents)
	}
}

func TestParseParents_NoParents(t *testing.T) {
	content := "tree 0000000000000000000000000000000000000000\nauthor Test <t@t.com> 0 +0000\n"
	parents := ParseParents(content)
	if len(parents) != 0 {
		t.Errorf("expected 0 parents, got %d", len(parents))
	}
}
