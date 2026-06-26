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
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/subcommands"
	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/policy"
	"github.com/project-oak/git-ratchet/internal/witness"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&checkpointCmd{}, "")
	subcommands.Register(&checkpointRequestCmd{}, "")
	subcommands.Register(&checkpointStoreCmd{}, "")
	subcommands.Register(&verifyCmd{}, "")
	subcommands.Register(&auditCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

type checkpointCmd struct {
	ref        string
	origin     string
	policyPath string
	keyPath    string
	kmsKey     string
	repoDir    string
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

`
}

func (c *checkpointCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to checkpoint (e.g. refs/heads/main or refs/tags/v1.0.0) (required)")
	f.StringVar(&c.origin, "origin", "", "Origin identity for the checkpoint (required for --kms-key, derived from --key if omitted)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.keyPath, "key", "", "Path to origin private key file (required unless --kms-key is set)")
	f.StringVar(&c.kmsKey, "kms-key", "", "GCP KMS key resource name for remote signing (alternative to --key)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *checkpointCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.ref == "" || c.policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --ref, --policy, and one of --key or --kms-key are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	if c.keyPath == "" && c.kmsKey == "" {
		fmt.Fprintln(os.Stderr, "error: --ref, --policy, and one of --key or --kms-key are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	if c.keyPath != "" && c.kmsKey != "" {
		fmt.Fprintln(os.Stderr, "error: --key and --kms-key are mutually exclusive")
		return subcommands.ExitUsageError
	}

	if _, err := gitutil.ParseRefKind(c.ref); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ref: %v\n", err)
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
	// Each witness gets its own 30-second deadline so a hung or slow witness
	// does not block the command indefinitely.
	type cosigResult struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses()
	ch := make(chan cosigResult, len(witnesses))
	for _, w := range witnesses {
		go func(w *policy.Witness) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			// Skip witnesses with non-HTTP endpoints.
			if w.Endpoint != "" && !strings.HasPrefix(w.Endpoint, "http://") && !strings.HasPrefix(w.Endpoint, "https://") {
				ch <- cosigResult{w.PolicyName, "", fmt.Errorf("unsupported witness transport %q (use checkpoint-request + checkpoint-store for non-HTTP witnesses)", w.Endpoint)}
				return
			}
			line, err := witness.Cosign(ctx, w.Endpoint, ancestry, signed)
			ch <- cosigResult{w.PolicyName, line, err}
		}(w)
	}
	var cosigLines []string
	for range witnesses {
		r := <-ch
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "warning: witness %s failed: %v\n", r.policyName, r.err)
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

	// Resolve commit hash from the ref.
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

type checkpointRequestCmd struct {
	ref           string
	origin        string
	keyPath       string
	kmsKey        string
	repoDir       string
	outputRequest string
	outputNote    string
}

func (*checkpointRequestCmd) Name() string { return "checkpoint-request" }
func (*checkpointRequestCmd) Synopsis() string {
	return "Produce an add-checkpoint request body without contacting witnesses"
}
func (*checkpointRequestCmd) Usage() string {
	return `checkpoint-request [flags]:
  Produce the add-checkpoint request body (ancestry proof + signed
  checkpoint note) without contacting any witnesses.

  The output can later be submitted to witnesses separately.
`
}

func (c *checkpointRequestCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to checkpoint (e.g. refs/heads/main or refs/tags/v1.0.0) (required)")
	f.StringVar(&c.origin, "origin", "", "Origin identity for the checkpoint (required for --kms-key, derived from --key if omitted)")
	f.StringVar(&c.keyPath, "key", "", "Path to origin private key file (required unless --kms-key is set)")
	f.StringVar(&c.kmsKey, "kms-key", "", "GCP KMS key resource name for remote signing (alternative to --key)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
	f.StringVar(&c.outputRequest, "output-request", "", "Write the full add-checkpoint wire format to this file (required)")
	f.StringVar(&c.outputNote, "output-note", "", "Write just the signed note to this file (required)")
}

func (c *checkpointRequestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.ref == "" || c.outputRequest == "" || c.outputNote == "" || (c.keyPath == "" && c.kmsKey == "") {
		fmt.Fprintln(os.Stderr, "error: --ref, --output-request, --output-note, and one of --key or --kms-key are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}
	if c.keyPath != "" && c.kmsKey != "" {
		fmt.Fprintln(os.Stderr, "error: --key and --kms-key are mutually exclusive")
		return subcommands.ExitUsageError
	}

	if _, err := gitutil.ParseRefKind(c.ref); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ref: %v\n", err)
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

	// Build the signed checkpoint note and ancestry proof.
	signed, ancestry, err := buildCheckpointRequest(c.repoDir, c.ref, origin, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}

	// Assemble wire-format request: ancestry lines, empty line, signed note.
	var wireFormat strings.Builder
	for _, line := range ancestry {
		wireFormat.WriteString(line)
		wireFormat.WriteString("\n")
	}
	wireFormat.WriteString("\n")
	wireFormat.WriteString(signed)
	request := wireFormat.String()

	// Write outputs.
	if err := os.WriteFile(c.outputRequest, []byte(request), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing request to %s: %v\n", c.outputRequest, err)
		return subcommands.ExitFailure
	}
	if err := os.WriteFile(c.outputNote, []byte(signed), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing note to %s: %v\n", c.outputNote, err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}

// stringSlice is a flag.Value that collects repeated --cosig flags.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }
func (s *stringSlice) Get() any           { return []string(*s) }

type checkpointStoreCmd struct {
	ref        string
	policyPath string
	notePath   string
	cosigPaths stringSlice
	repoDir    string
}

func (*checkpointStoreCmd) Name() string { return "checkpoint-store" }
func (*checkpointStoreCmd) Synopsis() string {
	return "Assemble and store a cosigned checkpoint from files"
}
func (*checkpointStoreCmd) Usage() string {
	return `checkpoint-store [flags]:
  Assemble a cosigned checkpoint from a signed note and cosignature files.

  Reads the signed note produced by checkpoint-request, appends each cosignature
  from the --cosig files, verifies the assembled checkpoint against the policy,
  and stores it as a Git ref.

  This command is intended for non-HTTP witnesses (e.g. github-issue://) where
  cosignatures are collected out-of-band.

`
}

func (c *checkpointStoreCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to checkpoint (e.g. refs/heads/main or refs/tags/v1.0.0) (required)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.notePath, "note", "", "Path to the signed note file (required)")
	f.Var(&c.cosigPaths, "cosig", "Path to a cosignature file (repeatable)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *checkpointStoreCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.ref == "" || c.policyPath == "" || c.notePath == "" {
		fmt.Fprintln(os.Stderr, "error: --ref, --policy, and --note are required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}

	if _, err := gitutil.ParseRefKind(c.ref); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ref: %v\n", err)
		return subcommands.ExitUsageError
	}

	// Read the signed note.
	noteData, err := os.ReadFile(c.notePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading note file: %v\n", err)
		return subcommands.ExitFailure
	}
	signed := string(noteData)

	// Read each cosignature file.
	var cosigLines []string
	for _, cosigPath := range c.cosigPaths {
		cosigData, err := os.ReadFile(cosigPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading cosignature file %s: %v\n", cosigPath, err)
			return subcommands.ExitFailure
		}
		cosigLines = append(cosigLines, strings.TrimSpace(string(cosigData)))
	}

	// Load the policy.
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}

	// Assemble cosignatures, verify quorum, and store.
	if err := assembleAndStoreCheckpoint(c.repoDir, c.ref, signed, cosigLines, pol); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return subcommands.ExitFailure
	}

	cpRef := "refs/checkpoints/" + strings.TrimPrefix(c.ref, "refs/")
	fmt.Printf("checkpoint stored at %s (%d cosignatures assembled)\n", cpRef, len(c.cosigPaths))
	return subcommands.ExitSuccess
}

type verifyCmd struct {
	refs       stringSlice
	policyPath string
	repoDir    string
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

	// Load the policy.
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}

	refs := []string(c.refs)

	// Verify refs in parallel.
	type verifyResult struct {
		ref string
		err error
	}
	results := make([]verifyResult, len(refs))
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			results[i] = verifyResult{ref, verifySingleRef(c.repoDir, ref, pol)}
		}(i, ref)
	}
	wg.Wait()

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
		fmt.Fprintf(os.Stderr, "\n%d of %d refs failed verification\n", failed, len(refs))
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
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

	// Extract the checkpointed commit hash from the note body.
	bodyLines := strings.Split(strings.TrimSpace(body), "\n")
	if len(bodyLines) < 2 {
		return fmt.Errorf("malformed checkpoint body")
	}
	checkpointedCommit := strings.TrimSpace(bodyLines[1])

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

type auditCmd struct {
	refs       stringSlice
	policyPath string
	repoDir    string
}

func (*auditCmd) Name() string     { return "audit" }
func (*auditCmd) Synopsis() string { return "Run a comprehensive integrity audit" }
func (*auditCmd) Usage() string {
	return `audit [flags]:
  Run a comprehensive integrity audit of the repository.

  Combines three checks into a single end-to-end integrity scan:

  1. git fsck: Walks the full object database and verifies that every
     object's content matches its hash, all referenced objects exist,
     and the DAG is well-formed.

  2. git-ratchet verify: Verifies checkpoints for the specified --ref
     flags against the witness policy.

  3. Replace ref rejection: Errors if any refs exist under refs/replace/.
     Replace refs allow transparent object substitution, breaking the
     Merkle chain property that git-ratchet relies on.

`
}

func (c *auditCmd) SetFlags(f *flag.FlagSet) {
	f.Var(&c.refs, "ref", "Full ref path to verify (e.g. refs/heads/main) (required, repeatable)")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *auditCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
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

	failed := 0

	// Phase 1: git fsck — verify object database integrity.
	fmt.Println("Running git fsck...")
	if err := gitutil.Fsck(c.repoDir); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL fsck: %v\n", err)
		failed++
	} else {
		fmt.Println("ok   fsck")
	}

	// Phase 2: git-ratchet verify — check all refs.
	fmt.Println("Running checkpoint verification...")
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitUsageError
	}
	refs := []string(c.refs)
	type verifyResult struct {
		ref string
		err error
	}
	results := make([]verifyResult, len(refs))
	var wg sync.WaitGroup
	for i, ref := range refs {
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			results[i] = verifyResult{ref, verifySingleRef(c.repoDir, ref, pol)}
		}(i, ref)
	}
	wg.Wait()
	for _, r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "FAIL verify %s: %v\n", r.ref, r.err)
			failed++
		} else {
			fmt.Printf("ok   verify %s\n", r.ref)
		}
	}

	// Phase 3: replace ref rejection.
	fmt.Println("Checking for replace refs...")
	replaceRefs, err := gitutil.ListReplaceRefs(c.repoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL replace-refs: %v\n", err)
		failed++
	} else if len(replaceRefs) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL replace-refs: found %d replace ref(s) (replace refs allow transparent object substitution, breaking Merkle chain integrity):\n", len(replaceRefs))
		for _, r := range replaceRefs {
			fmt.Fprintf(os.Stderr, "       %s\n", r)
		}
		failed++
	} else {
		fmt.Println("ok   replace-refs")
	}

	// Summary.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\naudit: %d check(s) failed\n", failed)
		return subcommands.ExitFailure
	}
	fmt.Println("\naudit: all checks passed")
	return subcommands.ExitSuccess
}
