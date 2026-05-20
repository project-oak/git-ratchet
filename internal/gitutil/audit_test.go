package gitutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

func TestFsck_CleanRepo(t *testing.T) {
	dir := initRepo(t)
	if err := Fsck(dir); err != nil {
		t.Errorf("Fsck on clean repo: %v", err)
	}
}

func TestFsck_CorruptedObject(t *testing.T) {
	dir := initRepo(t)

	// Find a pack or loose object to corrupt.
	objDir := filepath.Join(dir, ".git", "objects")
	var objPath string
	if err := filepath.Walk(objDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Loose objects are stored as .git/objects/<xx>/<rest>.
		// Skip "info" and "pack" directories.
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(objDir, path)
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) == 2 && len(parts[0]) == 2 {
			objPath = path
			return filepath.SkipAll
		}
		return nil
	}); err != nil {
		t.Fatalf("walking objects: %v", err)
	}
	if objPath == "" {
		t.Fatal("no loose object found to corrupt")
	}

	// Corrupt the object by overwriting its contents.
	if err := os.Chmod(objPath, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objPath, []byte("corrupted"), 0644); err != nil {
		t.Fatal(err)
	}

	err := Fsck(dir)
	if err == nil {
		t.Fatal("Fsck should fail on corrupted repo")
	}
	if !strings.Contains(err.Error(), "git fsck") {
		t.Errorf("expected error to mention git fsck, got: %v", err)
	}
}

func TestFsck_NotARepo(t *testing.T) {
	dir := t.TempDir()
	if err := Fsck(dir); err == nil {
		t.Fatal("Fsck should fail on non-repo directory")
	}
}

func TestListReplaceRefs_None(t *testing.T) {
	dir := initRepo(t)
	refs, err := ListReplaceRefs(dir)
	if err != nil {
		t.Fatalf("ListReplaceRefs: %v", err)
	}
	if len(refs) != 0 {
		t.Errorf("expected no replace refs, got %v", refs)
	}
}

func TestListReplaceRefs_Present(t *testing.T) {
	dir := initRepo(t)

	// Get the current HEAD commit hash.
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	originalCommit := strings.TrimSpace(string(out))

	// Make a second commit.
	if err := os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("world\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "second")

	cmd = exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	replacementCommit := strings.TrimSpace(string(out))

	// Create a replace ref: make the original commit "replaced by" the new one.
	run(t, dir, "git", "replace", originalCommit, replacementCommit)

	refs, err := ListReplaceRefs(dir)
	if err != nil {
		t.Fatalf("ListReplaceRefs: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected 1 replace ref, got %d: %v", len(refs), refs)
	}
	expectedRef := "refs/replace/" + originalCommit
	if refs[0] != expectedRef {
		t.Errorf("expected %s, got %s", expectedRef, refs[0])
	}
}

func TestListReplaceRefs_Multiple(t *testing.T) {
	dir := initRepo(t)

	// Create three commits so we can set up two replace refs.
	var commits []string
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	commits = append(commits, strings.TrimSpace(string(out)))

	for i := 0; i < 2; i++ {
		if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte(strings.Repeat("x", i+1)+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		run(t, dir, "git", "add", ".")
		run(t, dir, "git", "commit", "-m", "commit")
		cmd = exec.Command("git", "-C", dir, "rev-parse", "HEAD")
		out, err = cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		commits = append(commits, strings.TrimSpace(string(out)))
	}

	// Replace commit[0] with commit[1], and commit[1] with commit[2].
	run(t, dir, "git", "replace", commits[0], commits[1])
	run(t, dir, "git", "replace", commits[1], commits[2])

	refs, err := ListReplaceRefs(dir)
	if err != nil {
		t.Fatalf("ListReplaceRefs: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 replace refs, got %d: %v", len(refs), refs)
	}
}
