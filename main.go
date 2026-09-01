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

// git-ratchet: rollback-resistant Git branch checkpointing.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/subcommands"
	"github.com/project-oak/git-ratchet/internal/gitlog"
	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/policy"
	"github.com/project-oak/git-ratchet/internal/witness"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&logCmd{}, "")
	subcommands.Register(&checkpointCmd{}, "")
	subcommands.Register(&verifyCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

// witnessClient reaches witnesses over HTTP, and over github-issue by
// registering a transport for that scheme. The code that submits a checkpoint
// therefore does not know which carrier it got. The deadline is the caller's,
// via the request context.
func witnessClient(githubToken string) *http.Client {
	t := &http.Transport{}
	t.RegisterProtocol(witness.IssueScheme, &witness.IssueTransport{Token: githubToken})
	return &http.Client{Transport: t}
}

// requireGitHubToken reports whether the policy names a witness this client
// cannot reach without a token.
//
// Skipping such a witness would quietly lower the quorum, so an unreachable
// one is a usage error rather than a warning.
func requireGitHubToken(endpoints []string, token string) error {
	if token != "" {
		return nil
	}
	for _, e := range endpoints {
		if strings.HasPrefix(e, witness.IssueScheme+"://") {
			return fmt.Errorf("witness %s needs --github-token: a token that can open an issue on the witness repository", e)
		}
	}
	return nil
}

type checkpointCmd struct {
	origin      string
	policyPath  string
	keyPath     string
	kmsKey      string
	repoDir     string
	timeout     time.Duration
	githubToken string
}

func (*checkpointCmd) Name() string { return "checkpoint" }
func (*checkpointCmd) Synopsis() string {
	return "Get the transparency log's head cosigned by witnesses"
}
func (*checkpointCmd) Usage() string {
	return `checkpoint [flags]:
  Create a witnessed checkpoint of the repository's transparency log.

  Signs a checkpoint covering the whole log, submits it to the witnesses in
  the policy file, collects cosignatures, and stores the result.

  There is no --ref: a checkpoint covers whatever the log holds, and refs are
  recorded in it by "git-ratchet log". Witnesses cosign only that the log grew
  by appending. The ratchet rules -- a branch moving forward only, a tag never
  moving -- are enforced locally, by this command before it asks for
  cosignatures and by "git-ratchet verify" afterwards.

  The origin key can be provided as a local key file (--key) or as a
  GCP KMS key resource name (--kms-key). The origin identity is derived
  from the key file; use --origin to override (required when using --kms-key).

`
}

func (c *checkpointCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.origin, "origin", "", "Origin identity for the checkpoint (required for --kms-key, derived from --key if omitted)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.keyPath, "key", "", "Path to origin private key file (required unless --kms-key is set)")
	f.StringVar(&c.kmsKey, "kms-key", "", "GCP KMS key resource name for remote signing (alternative to --key)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
	f.DurationVar(&c.timeout, "witness-timeout", 30*time.Second, "How long to wait for each witness to cosign")
	f.StringVar(&c.githubToken, "github-token", "", "GitHub token for reaching github-issue:// witnesses")
}

func (c *checkpointCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.policyPath == "" || (c.keyPath == "" && c.kmsKey == "") {
		fmt.Fprintln(os.Stderr, "error: --policy and one of --key or --kms-key are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	if c.keyPath != "" && c.kmsKey != "" {
		fmt.Fprintln(os.Stderr, "error: --key and --kms-key are mutually exclusive")
		return subcommands.ExitUsageError
	}

	if c.kmsKey != "" && c.origin == "" {
		fmt.Fprintln(os.Stderr, "error: --origin is required when using --kms-key")
		return subcommands.ExitUsageError
	}

	// Load the origin signing key.
	var signer *note.Signer
	var err error
	if c.kmsKey != "" {
		signer, err = note.NewKMSSigner(context.Background(), c.origin, c.kmsKey, note.RoleOrigin)
	} else {
		signer, err = note.ReadKeyFile(c.keyPath, note.RoleOrigin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading key: %v\n", err)
		return subcommands.ExitFailure
	}

	// Use the origin name from the flag, or derive from the key.
	origin := c.origin
	if origin == "" {
		origin = signer.Name
	}

	return c.run(origin, signer)
}

// run checkpoints the repository's transparency log.
func (c *checkpointCmd) run(origin string, signer *note.Signer) subcommands.ExitStatus {
	pol, err := policy.FromPath(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}
	endpoints := make([]string, 0, len(pol.Witnesses))
	for _, w := range pol.Witnesses {
		if w.URL != nil {
			endpoints = append(endpoints, w.URL.String())
		}
	}
	if err := requireGitHubToken(endpoints, c.githubToken); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitUsageError
	}
	if err := checkpointLog(c.repoDir, origin, signer, pol, witnessClient(c.githubToken), c.timeout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

type logCmd struct {
	refs    stringSlice
	repoDir string
}

func (*logCmd) Name() string     { return "log" }
func (*logCmd) Synopsis() string { return "Record refs' current objects in the transparency log" }
func (*logCmd) Usage() string {
	return `log [flags]:
  Record each ref's current object in the repository's transparency log.

  This is the only command that grows the log. It is local: no key, and no
  witnesses are contacted. The new entries sit past the stored checkpoint
  until "git-ratchet checkpoint" has a quorum cosign the log's new head, and
  until then nothing verifies against them.

  A ref already at its latest logged state is skipped, so running this twice
  in a row does not grow the log. Pass --ref more than once to record several
  refs in a single entry batch.

`
}

func (c *logCmd) SetFlags(f *flag.FlagSet) {
	f.Var(&c.refs, "ref", "Full ref path to record (e.g. refs/heads/main or refs/tags/v1.0.0), repeatable (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *logCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if len(c.refs) == 0 {
		fmt.Fprintln(os.Stderr, "error: at least one --ref is required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	for _, ref := range c.refs {
		if _, err := gitutil.ParseRefKind(ref); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --ref %q: %v\n", ref, err)
			return subcommands.ExitUsageError
		}
	}

	if err := logRefs(c.repoDir, c.refs); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// stringSlice is a flag.Value that collects a repeated flag's values.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }
func (s *stringSlice) Get() any           { return []string(*s) }

type verifyCmd struct {
	refs       stringSlice
	policyPath string
	repoDir    string
}

func (*verifyCmd) Name() string     { return "verify" }
func (*verifyCmd) Synopsis() string { return "Verify refs against the witnessed transparency log" }
func (*verifyCmd) Usage() string {
	return `verify [flags]:
  Verify refs against the repository's witnessed transparency log.

  Checks the log's stored checkpoint against the policy -- the log's own
  signature and a quorum of witness cosignatures -- and then walks the logged
  entries for each ref. The --ref flag can be repeated to verify several refs
  in a single invocation.

  For branches, every logged state must descend from the one before it, and
  the local ref must not be ahead of the latest logged state. For tags, the
  tag must never have been logged at a second object, and must still point at
  the one it was logged at.

  Only the part of the log the checkpoint covers is read. Entries appended
  past the last cosigned checkpoint are not yet witnessed, so nothing verifies
  against them.

`
}

func (c *verifyCmd) SetFlags(f *flag.FlagSet) {
	f.Var(&c.refs, "ref", "Full ref path to verify (e.g. refs/heads/main) (required, repeatable)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *verifyCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.policyPath == "" || len(c.refs) == 0 {
		fmt.Fprintln(os.Stderr, "error: --policy and at least one --ref are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}

	for _, ref := range c.refs {
		if _, err := gitutil.ParseRefKind(ref); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --ref %q: %v\n", ref, err)
			return subcommands.ExitUsageError
		}
	}

	results := verifyRefs(c.repoDir, []string(c.refs), c.policyPath)

	failed := 0
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", r.ref, r.err)
			failed++
		} else {
			fmt.Printf("ok   %s\n", r.ref)
		}
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d of %d refs failed verification\n", failed, len(c.refs))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// verifyResult pairs a ref with the outcome of verifying it.
type verifyResult struct {
	ref string
	err error
}

// verifyRefs verifies each ref against the policy.
//
// The refs share one log, so its checkpoint is verified once up front -- a
// failure there fails every ref -- and the per-ref walks then run against that
// single verified log.
func verifyRefs(repoDir string, refs []string, policyPath string) []verifyResult {
	results := make([]verifyResult, len(refs))

	l, err := logFromPolicy(repoDir, policyPath)
	if err != nil {
		for i, ref := range refs {
			results[i] = verifyResult{ref, err}
		}
		return results
	}
	for i, ref := range refs {
		results[i] = verifyResult{ref, verifySingleRef(repoDir, ref, l)}
	}
	return results
}

// logFromPolicy loads a tlog-policy and returns the checkpointed part of
// the repository's log under it.
func logFromPolicy(repoDir, policyPath string) (*gitlog.Log, error) {
	pol, err := policy.FromPath(policyPath)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	return checkpointedLog(repoDir, pol)
}
