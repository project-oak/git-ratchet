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

package gitlog

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

// initRepo creates a new Git repository in a temp directory with one commit.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "--initial-branch=main", ".")
	run(t, dir, "git", "config", "user.email", "test@test.com")
	run(t, dir, "git", "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "initial")
	return dir
}

func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func mustOpen(t *testing.T, dir string) *Log {
	t.Helper()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return l
}

func TestOpenEmptyRepo(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)

	if l.Size() != 0 {
		t.Errorf("Size() = %d, want 0", l.Size())
	}
	if l.Head() != "" {
		t.Errorf("Head() = %q, want empty", l.Head())
	}
	if l.StoredCheckpoint() != "" {
		t.Errorf("StoredCheckpoint() = %q, want empty", l.StoredCheckpoint())
	}
	if l.Root() != tlog.EmptyRoot() {
		t.Error("an empty log should have the empty tree root")
	}
}

func TestAppendAndReopen(t *testing.T) {
	dir := initRepo(t)

	l := mustOpen(t, dir)
	l.Append(Entry{Ref: "refs/heads/main", Hash: "aaaa"})
	l.Append(Entry{Ref: "refs/tags/v1.0.0", Hash: "bbbb"})
	if err := l.Save("checkpoint-body", "log: two entries"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	wantRoot := l.Root()

	reopened := mustOpen(t, dir)
	if reopened.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", reopened.Size())
	}
	if reopened.Root() != wantRoot {
		t.Error("root changed across a save/reopen cycle")
	}
	if reopened.StoredCheckpoint() != "checkpoint-body" {
		t.Errorf("StoredCheckpoint() = %q", reopened.StoredCheckpoint())
	}
	entries := reopened.Entries()
	if entries[0].Ref != "refs/heads/main" || entries[0].Hash != "aaaa" {
		t.Errorf("entry 0 = %+v", entries[0])
	}
	if entries[1].Ref != "refs/tags/v1.0.0" || entries[1].Hash != "bbbb" {
		t.Errorf("entry 1 = %+v", entries[1])
	}
}

// TestSaveIsFastForward checks that each save chains onto the previous log
// commit, so the log ref only ever advances.
func TestSaveIsFastForward(t *testing.T) {
	dir := initRepo(t)

	l := mustOpen(t, dir)
	l.Append(Entry{Ref: "refs/heads/main", Hash: "aaaa"})
	if err := l.Save("cp1", "first"); err != nil {
		t.Fatal(err)
	}
	first := l.Head()

	l2 := mustOpen(t, dir)
	l2.Append(Entry{Ref: "refs/heads/main", Hash: "bbbb"})
	if err := l2.Save("cp2", "second"); err != nil {
		t.Fatal(err)
	}
	second := l2.Head()

	if first == second {
		t.Fatal("the second save should have produced a new commit")
	}
	// The new head must descend from the old one.
	out := run(t, dir, "git", "rev-list", "--first-parent", second)
	if !strings.Contains(out, first) {
		t.Errorf("log head %s does not descend from %s", second, first)
	}
}

// TestSaveRejectsConcurrentAdvance checks the compare-and-swap: a checkpointer
// holding a stale view must not clobber entries another writer appended.
func TestSaveRejectsConcurrentAdvance(t *testing.T) {
	dir := initRepo(t)

	l := mustOpen(t, dir)
	l.Append(Entry{Ref: "refs/heads/main", Hash: "aaaa"})
	if err := l.Save("cp1", "first"); err != nil {
		t.Fatal(err)
	}

	// Two writers both open at size 1.
	writerA := mustOpen(t, dir)
	writerB := mustOpen(t, dir)

	writerA.Append(Entry{Ref: "refs/heads/main", Hash: "bbbb"})
	if err := writerA.Save("cp2", "from A"); err != nil {
		t.Fatalf("first writer should succeed: %v", err)
	}

	writerB.Append(Entry{Ref: "refs/heads/other", Hash: "cccc"})
	if err := writerB.Save("cp2b", "from B"); err == nil {
		t.Error("expected the stale writer's save to be rejected")
	}

	// A's entry must still be there.
	final := mustOpen(t, dir)
	if final.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", final.Size())
	}
	if got, _ := final.Latest("refs/heads/main"); got.Hash != "bbbb" {
		t.Errorf("latest main entry = %+v, want bbbb", got)
	}
}

// TestBundleRollover exercises the transition from a partial entry bundle to a
// full one and on into a second bundle, which is where a stale partial-bundle
// path would survive into the tree if the tree were patched rather than
// rebuilt.
func TestBundleRollover(t *testing.T) {
	dir := initRepo(t)

	const total = EntriesPerBundle + 5
	l := mustOpen(t, dir)
	for i := 0; i < total; i++ {
		l.Append(Entry{Ref: "refs/heads/main", Hash: fmt.Sprintf("%04x", i)})
		if err := l.Save("cp", fmt.Sprintf("entry %d", i)); err != nil {
			t.Fatalf("Save at %d: %v", i, err)
		}
	}

	reopened := mustOpen(t, dir)
	if reopened.Size() != total {
		t.Fatalf("Size() = %d, want %d", reopened.Size(), total)
	}
	for i, e := range reopened.Entries() {
		if want := fmt.Sprintf("%04x", i); e.Hash != want {
			t.Fatalf("entry %d hash = %q, want %q", i, e.Hash, want)
		}
	}

	// The full first bundle must live at its unsuffixed path, and only the
	// second, still-partial bundle may carry a ".p/" suffix.
	paths := run(t, dir, "git", "ls-tree", "-r", "--name-only", LogRef, "tile/entries/")
	if !strings.Contains(paths, "tile/entries/000\n") && !strings.HasSuffix(paths, "tile/entries/000") {
		t.Errorf("expected a full bundle at tile/entries/000, got:\n%s", paths)
	}
	if !strings.Contains(paths, "tile/entries/001.p/5") {
		t.Errorf("expected a partial bundle at tile/entries/001.p/5, got:\n%s", paths)
	}
	if strings.Contains(paths, "tile/entries/000.p/") {
		t.Errorf("a superseded partial bundle survived into the tree:\n%s", paths)
	}
}

func TestEntriesForAndLatest(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(Entry{Ref: "refs/heads/main", Hash: "a1"})
	l.Append(Entry{Ref: "refs/heads/dev", Hash: "b1"})
	l.Append(Entry{Ref: "refs/heads/main", Hash: "a2"})
	if err := l.Save("cp", "entries"); err != nil {
		t.Fatal(err)
	}

	mains := l.EntriesFor("refs/heads/main")
	if len(mains) != 2 || mains[0].Hash != "a1" || mains[1].Hash != "a2" {
		t.Errorf("EntriesFor(main) = %+v", mains)
	}
	latest, ok := l.Latest("refs/heads/main")
	if !ok || latest.Hash != "a2" {
		t.Errorf("Latest(main) = %+v, %v", latest, ok)
	}
	if _, ok := l.Latest("refs/heads/absent"); ok {
		t.Error("Latest should report absence for an unlogged ref")
	}
}

// TestProofsAgainstStoredLog checks that proofs generated from a reopened log
// verify against the roots the log reports.
func TestProofsAgainstStoredLog(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	for i := 0; i < 20; i++ {
		l.Append(Entry{Ref: "refs/heads/main", Hash: fmt.Sprintf("%04x", i)})
	}
	if err := l.Save("cp", "twenty entries"); err != nil {
		t.Fatal(err)
	}

	reopened := mustOpen(t, dir)
	root := reopened.Root()

	for i := 0; i < 20; i++ {
		proof, err := reopened.InclusionProof(i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		leaf := reopened.Entries()[i].LeafHash()
		if err := tlog.VerifyInclusion(leaf, root, proof, i, 20); err != nil {
			t.Errorf("VerifyInclusion(%d): %v", i, err)
		}
	}

	for m := 0; m <= 20; m++ {
		proof, err := reopened.ConsistencyProofFrom(m)
		if err != nil {
			t.Fatalf("ConsistencyProofFrom(%d): %v", m, err)
		}
		oldRoot, err := reopened.RootAt(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := tlog.VerifyConsistency(oldRoot, root, proof, m, 20); err != nil {
			t.Errorf("VerifyConsistency(%d): %v", m, err)
		}
	}
}

func TestParseEntry(t *testing.T) {
	e, err := ParseEntry("refs/heads/main deadbeef")
	if err != nil {
		t.Fatalf("ParseEntry: %v", err)
	}
	if e.Ref != "refs/heads/main" || e.Hash != "deadbeef" {
		t.Errorf("ParseEntry = %+v", e)
	}
	if e.String() != "refs/heads/main deadbeef" {
		t.Errorf("String() = %q", e.String())
	}

	for _, bad := range []string{
		"refs/heads/main",
		"refs/heads/main deadbeef extra",
		"refs/notes/x deadbeef",
		"",
	} {
		if _, err := ParseEntry(bad); err == nil {
			t.Errorf("ParseEntry(%q): expected an error", bad)
		}
	}
}

func TestRootAtOutOfRange(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(Entry{Ref: "refs/heads/main", Hash: "aa"})
	if _, err := l.RootAt(2); err == nil {
		t.Error("expected an error for a size beyond the log")
	}
	if _, err := l.RootAt(-1); err == nil {
		t.Error("expected an error for a negative size")
	}
}
