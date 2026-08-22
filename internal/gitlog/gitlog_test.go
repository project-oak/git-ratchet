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

// obj expands a short label into a valid 40-character hex object hash, so
// tests can stay readable while exercising the real validation rules.
func obj(label string) string {
	h := label
	if len(h) > 40 {
		h = h[:40]
	}
	return h + strings.Repeat("0", 40-len(h))
}

// mustRefUpdate builds a ref-update entry or fails the test.
func mustRefUpdate(t *testing.T, ref, object string) Entry {
	t.Helper()
	e, err := NewRefUpdate(ref, object)
	if err != nil {
		t.Fatalf("NewRefUpdate(%q, %q): %v", ref, object, err)
	}
	return e
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
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aaaa")))
	l.Append(mustRefUpdate(t, "refs/tags/v1.0.0", obj("bbbb")))
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
	for i, want := range []RefUpdate{
		{Ref: "refs/heads/main", Object: obj("aaaa")},
		{Ref: "refs/tags/v1.0.0", Object: obj("bbbb")},
	} {
		got, err := entries[i].AsRefUpdate()
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if got != want {
			t.Errorf("entry %d = %+v, want %+v", i, got, want)
		}
	}
}

// TestSaveIsFastForward checks that each save chains onto the previous log
// commit, so the log ref only ever advances.
func TestSaveIsFastForward(t *testing.T) {
	dir := initRepo(t)

	l := mustOpen(t, dir)
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aaaa")))
	if err := l.Save("cp1", "first"); err != nil {
		t.Fatal(err)
	}
	first := l.Head()

	l2 := mustOpen(t, dir)
	l2.Append(mustRefUpdate(t, "refs/heads/main", obj("bbbb")))
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
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aaaa")))
	if err := l.Save("cp1", "first"); err != nil {
		t.Fatal(err)
	}

	// Two writers both open at size 1.
	writerA := mustOpen(t, dir)
	writerB := mustOpen(t, dir)

	writerA.Append(mustRefUpdate(t, "refs/heads/main", obj("bbbb")))
	if err := writerA.Save("cp2", "from A"); err != nil {
		t.Fatalf("first writer should succeed: %v", err)
	}

	writerB.Append(mustRefUpdate(t, "refs/heads/other", obj("cccc")))
	if err := writerB.Save("cp2b", "from B"); err == nil {
		t.Error("expected the stale writer's save to be rejected")
	}

	// A's entry must still be there.
	final := mustOpen(t, dir)
	if final.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", final.Size())
	}
	mains, err := final.RefUpdates("refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(mains) != 2 || mains[len(mains)-1].Object != obj("bbbb") {
		t.Errorf("main entries = %+v, want latest %s", mains, obj("bbbb"))
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
		l.Append(mustRefUpdate(t, "refs/heads/main", obj(fmt.Sprintf("%04x", i))))
		if err := l.Save("cp", fmt.Sprintf("entry %d", i)); err != nil {
			t.Fatalf("Save at %d: %v", i, err)
		}
	}

	reopened := mustOpen(t, dir)
	if reopened.Size() != total {
		t.Fatalf("Size() = %d, want %d", reopened.Size(), total)
	}
	for i, e := range reopened.Entries() {
		ru, err := e.AsRefUpdate()
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		if want := obj(fmt.Sprintf("%04x", i)); ru.Object != want {
			t.Fatalf("entry %d object = %q, want %q", i, ru.Object, want)
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

func TestRefUpdatesFiltersByRef(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("a1")))
	l.Append(mustRefUpdate(t, "refs/heads/dev", obj("b1")))
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("a2")))
	if err := l.Save("cp", "entries"); err != nil {
		t.Fatal(err)
	}

	mains, err := l.RefUpdates("refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(mains) != 2 || mains[0].Object != obj("a1") || mains[1].Object != obj("a2") {
		t.Errorf("RefUpdates(main) = %+v", mains)
	}

	absent, err := l.RefUpdates("refs/heads/absent")
	if err != nil {
		t.Fatal(err)
	}
	if len(absent) != 0 {
		t.Errorf("RefUpdates(absent) = %+v, want none", absent)
	}
}

// TestProofsAgainstStoredLog checks that proofs generated from a reopened log
// verify against the roots the log reports.
func TestProofsAgainstStoredLog(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	for i := 0; i < 20; i++ {
		l.Append(mustRefUpdate(t, "refs/heads/main", obj(fmt.Sprintf("%04x", i))))
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

func TestRootAtOutOfRange(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aa")))
	if _, err := l.RootAt(2); err == nil {
		t.Error("expected an error for a size beyond the log")
	}
	if _, err := l.RootAt(-1); err == nil {
		t.Error("expected an error for a negative size")
	}
}

// TestCheckEntryTypesFailsClosed covers forward compatibility at the log
// level: a log carrying a statement this implementation cannot interpret must
// be refused outright, not verified for the part of it that happens to be
// legible.
func TestCheckEntryTypesFailsClosed(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aaaa")))

	future, err := ParseEntry([]byte(`{"type":"git-ratchet/tombstone/v1","commit":"` + obj("dead") + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	l.Append(future)
	if err := l.Save("cp", "with a future entry"); err != nil {
		t.Fatal(err)
	}

	reopened := mustOpen(t, dir)
	if reopened.Size() != 2 {
		t.Fatalf("Size() = %d, want 2", reopened.Size())
	}
	err = reopened.CheckEntryTypes()
	if err == nil {
		t.Fatal("expected an unrecognised critical entry to be refused")
	}
	if !strings.Contains(err.Error(), "unrecognised critical type") {
		t.Errorf("unexpected diagnostic: %v", err)
	}

	// The ref-update entries alongside it are still readable; refusing is a
	// policy decision made by the verifier, not a parse failure.
	mains, err := reopened.RefUpdates("refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(mains) != 1 {
		t.Errorf("RefUpdates(main) = %+v, want one entry", mains)
	}
}

// TestCheckEntryTypesAllowsNonCritical checks the escape hatch for entry types
// a future version may add that are genuinely safe to skip.
func TestCheckEntryTypesAllowsNonCritical(t *testing.T) {
	dir := initRepo(t)
	l := mustOpen(t, dir)
	l.Append(mustRefUpdate(t, "refs/heads/main", obj("aaaa")))

	optional, err := ParseEntry([]byte(`{"type":"git-ratchet/annotation/v1","critical":false,"note":"hi"}`))
	if err != nil {
		t.Fatal(err)
	}
	l.Append(optional)
	if err := l.Save("cp", "with an optional entry"); err != nil {
		t.Fatal(err)
	}

	if err := mustOpen(t, dir).CheckEntryTypes(); err != nil {
		t.Errorf("a non-critical unknown entry should be tolerated: %v", err)
	}
}
