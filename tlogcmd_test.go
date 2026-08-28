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

package main

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/project-oak/git-ratchet/internal/gitlog"
	"github.com/project-oak/git-ratchet/internal/gitutil"
)

// chainTestRepo builds a repository with two commits on a line and one that
// diverges from the first, and returns their hashes.
func chainTestRepo(t *testing.T) (dir, first, second, divergent string) {
	t.Helper()
	dir = t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(cmd.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %s: %v", strings.Join(args, " "), out, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q", "-b", "main")
	git("commit", "-q", "--allow-empty", "-m", "first")
	first = git("rev-parse", "HEAD")
	git("commit", "-q", "--allow-empty", "-m", "second")
	second = git("rev-parse", "HEAD")
	git("checkout", "-q", "-b", "other", first)
	git("commit", "-q", "--allow-empty", "-m", "divergent")
	divergent = git("rev-parse", "HEAD")
	return dir, first, second, divergent
}

// TestCheckRefChain covers the rule verify applies to a log's entries.
//
// checkpoint refuses to write a log that breaks it, so reaching this in
// practice means the log came from somewhere else: another implementation, or
// a hand-edited ref. The rule has to hold on its own for that reason, which is
// why it is tested here rather than only through the command.
func TestCheckRefChain(t *testing.T) {
	dir, first, second, divergent := chainTestRepo(t)

	rec := func(ref string, objects ...string) []gitlog.RefRecord {
		out := make([]gitlog.RefRecord, 0, len(objects))
		for _, o := range objects {
			out = append(out, gitlog.RefRecord{Ref: ref, Object: o})
		}
		return out
	}

	const branch = "refs/heads/main"
	const tag = "refs/tags/v1"

	for _, tc := range []struct {
		name    string
		ref     string
		kind    gitutil.RefKind
		records []gitlog.RefRecord
		wantErr string
	}{
		{"branch moving forward", branch, gitutil.RefBranch, rec(branch, first, second), ""},
		{"branch unchanged", branch, gitutil.RefBranch, rec(branch, first, first), ""},
		{"branch single entry", branch, gitutil.RefBranch, rec(branch, second), ""},
		{"branch rolled back", branch, gitutil.RefBranch, rec(branch, second, first), "history was rewritten"},
		{"branch diverged", branch, gitutil.RefBranch, rec(branch, second, divergent), "history was rewritten"},
		{"tag once", tag, gitutil.RefTag, rec(tag, first), ""},
		{"tag moved", tag, gitutil.RefTag, rec(tag, first, second), "a tag must be logged at one object only"},
		{"tag repeated at one object", tag, gitutil.RefTag, rec(tag, first, first, first), ""},
		{"tag moved away and back", tag, gitutil.RefTag, rec(tag, first, second, first), "a tag must be logged at one object only"},
		{"branch repeated then forward", branch, gitutil.RefBranch, rec(branch, first, first, second), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRefChain(dir, tc.ref, tc.kind, tc.records)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestCheckRefChainMissingObject covers the diagnostic for a logged commit the
// repository can no longer produce, which is what a rollback followed by
// garbage collection looks like from here.
func TestCheckRefChainMissingObject(t *testing.T) {
	dir, first, _, _ := chainTestRepo(t)
	const branch = "refs/heads/main"
	records := []gitlog.RefRecord{
		{Ref: branch, Object: first},
		{Ref: branch, Object: strings.Repeat("0", len(first))},
	}
	err := checkRefChain(dir, branch, gitutil.RefBranch, records)
	if err == nil {
		t.Fatal("expected an error for a commit missing from the object database")
	}
	if !strings.Contains(err.Error(), "logged history was discarded") {
		t.Errorf("error should explain what a missing object means, got: %v", err)
	}
}

// TestCosignatureFromResponse covers reading a witness's add-checkpoint
// response. A refusal has to be told from a cosignature: appending the body of
// a 409 to the note would leave the checkpoint short of quorum, with nothing
// saying why.
func TestCosignatureFromResponse(t *testing.T) {
	msg := func(status, headers, body string) string {
		return "HTTP/1.1 " + status + "\nContent-Length: " +
			strconv.Itoa(len(body)) + "\n" + headers + "\n" + body
	}

	for _, tc := range []struct {
		name    string
		message string
		want    string
		wantErr string
	}{
		{
			name:    "cosignature",
			message: msg("200 OK", "", "— w1 AAAA\n"),
			want:    "— w1 AAAA",
		},
		{
			name:    "size conflict names the size the witness holds",
			message: msg("409 Conflict", "Content-Type: text/x.tlog.size\n", "7\n"),
			wantErr: "witness holds tree size 7",
		},
		{
			name:    "conflict without a size is a different tree",
			message: msg("409 Conflict", "", ""),
			wantErr: "different tree",
		},
		{
			name:    "refusal is reported, not assembled",
			message: msg("403 Forbidden", "", ""),
			wantErr: "403",
		},
		{
			name:    "not a message",
			message: "— w1 AAAA\n",
			wantErr: "parsing response message",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cosignatureFromResponse(tc.message)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got %q", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
