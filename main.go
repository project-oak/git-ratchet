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
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
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

// witnessClient returns a client that reaches witnesses over HTTP, which is
// every witness git-checkpoint mode has. The deadline is the caller's, via the
// request context.
func witnessClient() *http.Client {
	return &http.Client{}
}

// tlogWitnessClient also reaches github-issue witnesses, which only tlog mode
// has, by registering a transport for their scheme. The code that submits a
// checkpoint therefore does not know which carrier it got.
func tlogWitnessClient(githubToken string) *http.Client {
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
	ref         string
	origin      string
	policyPath  string
	keyPath     string
	kmsKey      string
	repoDir     string
	mode        string
	timeout     time.Duration
	githubToken string
}

func (*checkpointCmd) Name() string     { return "checkpoint" }
func (*checkpointCmd) Synopsis() string { return "Create a witnessed checkpoint for a branch or tag" }
func (*checkpointCmd) Usage() string {
	return `checkpoint [flags]:
  Create a witnessed checkpoint for a branch or tag.

  Signs a checkpoint for the ref, submits it to the witnesses in the policy
  file, collects cosignatures, and stores the cosigned checkpoint as a Git
  ref (refs/checkpoints/heads/<branch> or refs/checkpoints/tags/<tag>).

  The origin key can be provided as a local key file (--key) or as a
  GCP KMS key resource name (--kms-key). The origin identity is derived
  from the key file; use --origin to override (required when using --kms-key).

  For branches (refs/heads/*), witnesses enforce a forward-only ratchet: the
  new commit must be a descendant of the previously witnessed commit.

  For tags (refs/tags/*), witnesses enforce immutability: the tag is pinned to
  the first commit it is witnessed at, and any subsequent checkpoint with a
  different commit is rejected.

  With --mode ` + modeTlog + ` there is no --ref: the checkpoint covers the whole
  transparency log, and refs are recorded in it by "git-ratchet log". Witnesses
  cosign only that the log grew by appending; the ratchet rules above are
  enforced locally, by this command before it asks for cosignatures and by
  "git-ratchet verify" afterwards.

`
}

func (c *checkpointCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to checkpoint (e.g. refs/heads/main or refs/tags/v1.0.0) (required)")
	f.StringVar(&c.origin, "origin", "", "Origin identity for the checkpoint (required for --kms-key, derived from --key if omitted)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.keyPath, "key", "", "Path to origin private key file (required unless --kms-key is set)")
	f.StringVar(&c.kmsKey, "kms-key", "", "GCP KMS key resource name for remote signing (alternative to --key)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
	f.StringVar(&c.mode, "mode", modeGitCheckpoint, "Checkpoint format: "+modeGitCheckpoint+" or "+modeTlog)
	f.DurationVar(&c.timeout, "witness-timeout", 30*time.Second, "How long to wait for each witness to cosign")
	f.StringVar(&c.githubToken, "github-token", "", "GitHub token for reaching github-issue:// witnesses")
}

func (c *checkpointCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := validateMode(c.mode); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitUsageError
	}
	if err := checkpointRefFlag(c.mode, c.ref); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
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

	// The two modes read different policy grammars and reach witnesses
	// differently; see internal/policy/tlog.go.
	if c.mode == modeTlog {
		return c.executeTlog(origin, signer)
	}
	return c.executeGitCheckpoint(origin, signer)
}

// executeTlog checkpoints the repository's transparency log.
func (c *checkpointCmd) executeTlog(origin string, signer *note.Signer) subcommands.ExitStatus {
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
	if err := checkpointTlog(c.repoDir, origin, signer, pol, tlogWitnessClient(c.githubToken), c.timeout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

// executeGitCheckpoint signs one ref's checkpoint, collects cosignatures from
// the policy's witnesses, and stores the result.
func (c *checkpointCmd) executeGitCheckpoint(origin string, signer *note.Signer) subcommands.ExitStatus {
	// Load the policy for witnesses and quorum (the log line is not
	// used on the checkpointer side — the origin knows its own identity).
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}

	// Phase 1: Build the signed checkpoint note and ancestry proof.
	signed, ancestry, err := buildCheckpointRequest(c.repoDir, c.ref, origin, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}

	// Phase 2: Collect cosignatures from witnesses in parallel.
	// Each witness gets its own deadline so a hung or slow witness does not
	// block the command indefinitely.
	client := witnessClient()
	type cosigResult struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses()
	ch := make(chan cosigResult, len(witnesses))
	for _, w := range witnesses {
		go func(w *policy.Witness) {
			ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
			defer cancel()
			// Skip witnesses with non-HTTP endpoints.
			if w.Endpoint != "" && !strings.HasPrefix(w.Endpoint, "http://") && !strings.HasPrefix(w.Endpoint, "https://") {
				ch <- cosigResult{w.PolicyName, "", fmt.Errorf("unsupported witness transport %q: %s mode reaches witnesses over HTTP only", w.Endpoint, modeGitCheckpoint)}
				return
			}
			line, err := witness.Cosign(ctx, client, w.Endpoint, ancestry, signed)
			ch <- cosigResult{w.PolicyName, line, err}
		}(w)
	}
	var cosigLines []string
	for range witnesses {
		r := <-ch
		if r.err != nil {
			// A witness rejection (e.g. HTTP 422: ancestry proof
			// failed) is the strongest signal that a rollback may
			// be in progress. Treat it as a hard error — do not
			// silently skip it just because other witnesses might
			// still satisfy quorum.
			var rejection *witness.RejectionError
			if errors.As(r.err, &rejection) {
				fmt.Fprintf(os.Stderr, "error: witness %s rejected checkpoint: %v\n", r.policyName, r.err)
				return subcommands.ExitFailure
			}
			// Transient failures (timeouts, network errors, 5xx)
			// are logged as warnings; the quorum check below will
			// catch the case where too few witnesses responded.
			fmt.Fprintf(os.Stderr, "warning: witness %s failed (skipped): %v\n", r.policyName, r.err)
			continue
		}
		cosigLines = append(cosigLines, r.cosigLine)
	}

	// Phase 3: Assemble cosignatures, verify quorum, and store.
	if err := assembleAndStoreCheckpoint(c.repoDir, c.ref, signed, cosigLines, pol); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}

	cpRef := "refs/checkpoints/" + strings.TrimPrefix(c.ref, "refs/")
	fmt.Printf("checkpoint stored at %s (%d witness cosignatures)\n", cpRef, len(cosigLines))
	return subcommands.ExitSuccess
}

// buildCheckpointRequest signs a checkpoint for the given ref and builds the
// ancestry proof (for branches). It returns the signed note and the ancestry
// lines. This is the shared core logic used by both the checkpoint and
// checkpoint-request subcommands.
func buildCheckpointRequest(repoDir, ref, origin string, signer *note.Signer) (signedNote string, ancestry []string, err error) {
	kind, err := gitutil.ParseRefKind(ref)
	if err != nil {
		return "", nil, fmt.Errorf("invalid ref: %v", err)
	}

	// Resolve object hash from the ref.
	commit, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return "", nil, fmt.Errorf("resolving ref: %v", err)
	}

	// Build the checkpoint body.
	body := origin + " " + ref + "\n" + commit + "\n"

	// Sign the checkpoint.
	signed, err := note.Sign(body, signer)
	if err != nil {
		return "", nil, fmt.Errorf("signing checkpoint: %v", err)
	}

	// Build ancestry proof (branches only; tags don't need one).
	if kind == gitutil.RefBranch {
		if oldCheckpoint, err := gitutil.ReadCheckpoint(repoDir, ref); err == nil {
			oldBody, err := note.ExtractBody(oldCheckpoint)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(oldBody), "\n")
				if len(lines) >= 2 {
					oldCommit := strings.TrimSpace(lines[1])
					ancestry, err = gitutil.GetCommitChain(repoDir, oldCommit, commit)
					if err != nil {
						return "", nil, fmt.Errorf("generating ancestry proof: %v", err)
					}
				}
			}
		}
	}

	return signed, ancestry, nil
}

// assembleAndStoreCheckpoint appends cosignature lines to a signed note,
// verifies the assembled checkpoint against the policy quorum, and stores it
// as a Git ref. This is the shared core logic used by both the checkpoint and
// checkpoint-store subcommands.
func assembleAndStoreCheckpoint(repoDir, ref, signedNote string, cosigLines []string, pol *policy.Policy) error {
	// Append cosignatures.
	assembled := signedNote
	for _, cosigLine := range cosigLines {
		assembled = note.AppendSignature(assembled, cosigLine)
	}

	// Verify the assembled checkpoint satisfies the policy quorum.
	assembledBody, assembledSigLines, err := note.ParseSignedNote(assembled)
	if err != nil {
		return fmt.Errorf("parsing assembled checkpoint: %v", err)
	}
	if err := pol.VerifyQuorum(assembledBody, assembledSigLines); err != nil {
		return fmt.Errorf("quorum not satisfied: %v", err)
	}

	// Store the checkpoint as a git ref.
	if err := gitutil.StoreCheckpoint(repoDir, ref, assembled); err != nil {
		return fmt.Errorf("storing checkpoint: %v", err)
	}

	return nil
}

type logCmd struct {
	refs    stringSlice
	repoDir string
	mode    string
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

  Only supported with --mode ` + modeTlog + `; ` + modeGitCheckpoint + ` mode has no log.

`
}

func (c *logCmd) SetFlags(f *flag.FlagSet) {
	f.Var(&c.refs, "ref", "Full ref path to record (e.g. refs/heads/main or refs/tags/v1.0.0), repeatable (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
	f.StringVar(&c.mode, "mode", modeGitCheckpoint, "Checkpoint format: "+modeGitCheckpoint+" or "+modeTlog)
}

func (c *logCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := validateMode(c.mode); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitUsageError
	}
	if c.mode != modeTlog {
		fmt.Fprintf(os.Stderr, "error: log requires --mode %s: %s mode keeps no log, and its checkpoints "+
			"are made one ref at a time with `git-ratchet checkpoint --ref`\n", modeTlog, modeGitCheckpoint)
		return subcommands.ExitUsageError
	}
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

	if err := logRefsTlog(c.repoDir, c.refs); err != nil {
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
	mode       string
}

func (*verifyCmd) Name() string     { return "verify" }
func (*verifyCmd) Synopsis() string { return "Verify ref checkpoints against a witness policy" }
func (*verifyCmd) Usage() string {
	return `verify [flags]:
  Verify ref checkpoints against a witness policy.

  Verifies checkpoint signatures against the policy and confirms each ref
  still matches the checkpointed commit. The --ref flag can be repeated to
  verify multiple refs in a single invocation.

  For branches, the local ref must not be ahead of the checkpointed commit.
  For tags, the tag must still point to the exact checkpointed commit.

`
}

func (c *verifyCmd) SetFlags(f *flag.FlagSet) {
	f.Var(&c.refs, "ref", "Full ref path to verify (e.g. refs/heads/main) (required, repeatable)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
	f.StringVar(&c.mode, "mode", modeGitCheckpoint, "Checkpoint format: "+modeGitCheckpoint+" or "+modeTlog)
}

func (c *verifyCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if err := validateMode(c.mode); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitUsageError
	}
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

	results := verifyRefs(c.repoDir, []string(c.refs), c.policyPath, c.mode)

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

// verifyRefs verifies each ref against the policy in the given mode.
//
// The two modes parallelise differently. A git-checkpoint verification is
// independent per ref, so those run concurrently. A tlog verification shares
// one log: its checkpoint is verified once up front — a failure there fails
// every ref — and the per-ref walks then run against that single verified log.
func verifyRefs(repoDir string, refs []string, policyPath string, mode string) []verifyResult {
	results := make([]verifyResult, len(refs))

	if mode == modeTlog {
		l, err := tlogLogFromPolicy(repoDir, policyPath)
		if err != nil {
			for i, ref := range refs {
				results[i] = verifyResult{ref, err}
			}
			return results
		}
		for i, ref := range refs {
			results[i] = verifyResult{ref, verifySingleRefTlog(repoDir, ref, l)}
		}
		return results
	}

	pol, err := policy.Load(policyPath)
	if err != nil {
		for i, ref := range refs {
			results[i] = verifyResult{ref, fmt.Errorf("loading policy: %w", err)}
		}
		return results
	}

	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			results[i] = verifyResult{ref, verifySingleRef(repoDir, ref, pol)}
		}(i, ref)
	}
	wg.Wait()
	return results
}

// tlogLogFromPolicy loads a tlog-policy and returns the checkpointed part of
// the repository's log under it.
func tlogLogFromPolicy(repoDir, policyPath string) (*gitlog.Log, error) {
	tpol, err := policy.FromPath(policyPath)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}
	return checkpointedLog(repoDir, tpol)
}

// verifySingleRef verifies a single ref's checkpoint against the policy.
func verifySingleRef(repoDir, ref string, pol *policy.Policy) error {
	kind, err := gitutil.ParseRefKind(ref)
	if err != nil {
		return err
	}

	// Read the stored checkpoint.
	checkpoint, err := gitutil.ReadCheckpoint(repoDir, ref)
	if err != nil {
		cpRef := "refs/checkpoints/" + strings.TrimPrefix(ref, "refs/")
		return fmt.Errorf("no checkpoint found for ref %q (hint: git fetch origin %s:%s)", ref, cpRef, cpRef)
	}

	// Parse the signed note.
	body, sigLines, err := note.ParseSignedNote(checkpoint)
	if err != nil {
		return fmt.Errorf("parsing checkpoint: %w", err)
	}

	// Verify origin signature and witness cosignatures.
	if err := pol.Verify(body, sigLines); err != nil {
		return fmt.Errorf("checkpoint verification failed: %w", err)
	}

	// Extract and validate the origin, ref, and commit from the checkpoint body.
	cpOrigin, cpRef, checkpointedCommit, err := note.ParseCheckpointBody(body)
	if err != nil {
		return fmt.Errorf("malformed checkpoint body: %w", err)
	}
	if cpRef != ref {
		return fmt.Errorf("checkpoint ref mismatch: checkpoint is for %q but verifying %q", cpRef, ref)
	}
	if cpOrigin != pol.LogName {
		return fmt.Errorf("checkpoint origin mismatch: checkpoint is from %q but policy expects %q", cpOrigin, pol.LogName)
	}

	// Resolve the current commit from the ref.
	localCommit, err := gitutil.ResolveRef(repoDir, ref)
	if err != nil {
		return fmt.Errorf("resolving ref: %w", err)
	}

	if kind == gitutil.RefTag {
		// Tag pinning: current commit must exactly match checkpoint.
		if localCommit != checkpointedCommit {
			return fmt.Errorf("tag does not match checkpoint (current: %s, checkpointed: %s)", localCommit, checkpointedCommit)
		}
	} else {
		// Branch ratchet: local commit must be ancestor-or-equal of the
		// checkpointed commit. If it is ahead, those commits are
		// unwitnessed and could be silently removed.
		ok, err := gitutil.IsAncestor(repoDir, localCommit, checkpointedCommit)
		if err != nil {
			return fmt.Errorf("checking ancestry: %w", err)
		}
		if !ok {
			return fmt.Errorf("local commit %s is ahead of checkpointed commit %s", localCommit, checkpointedCommit)
		}
	}

	return nil
}
