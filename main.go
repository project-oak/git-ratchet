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

	"github.com/BenBirt/git-ratchet/internal/gitutil"
	"github.com/BenBirt/git-ratchet/internal/note"
	"github.com/BenBirt/git-ratchet/internal/policy"
	"github.com/BenBirt/git-ratchet/internal/witness"
	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")

	subcommands.Register(&checkpointCmd{}, "")
	subcommands.Register(&verifyCmd{}, "")
	subcommands.Register(&auditCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}

type checkpointCmd struct {
	ref        string
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
  GCP KMS key resource name (--kms-key).

  For branches (refs/heads/*), witnesses enforce a forward-only ratchet: the
  new commit must be a descendant of the previously witnessed commit.

  For tags (refs/tags/*), witnesses enforce immutability: the tag is pinned to
  the first commit it is witnessed at, and any subsequent checkpoint with a
  different commit is rejected.

`
}

func (c *checkpointCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to checkpoint (e.g. refs/heads/main or refs/tags/v1.0.0) (required)")
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

	kind, err := gitutil.ParseRefKind(c.ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid --ref: %v\n", err)
		return subcommands.ExitUsageError
	}

	// Load the policy first — we need pol.LogName for KMS signer identity.
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}

	// Load the origin signing key.
	var signer *note.Signer
	if c.kmsKey != "" {
		signer, err = note.NewKMSSigner(context.Background(), pol.LogName, c.kmsKey, note.RoleOrigin)
	} else {
		signer, err = note.ReadKeyFile(c.keyPath, note.RoleOrigin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading key: %v\n", err)
		return subcommands.ExitFailure
	}

	// Resolve commit hash from the ref.
	commit, err := gitutil.ResolveRef(c.repoDir, c.ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: resolving ref: %v\n", err)
		return subcommands.ExitFailure
	}

	// Build the checkpoint body using the log name from the policy.
	body := pol.LogName + " " + c.ref + "\n" + commit + "\n"

	// Sign the checkpoint.
	signed, err := note.Sign(body, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: signing checkpoint: %v\n", err)
		return subcommands.ExitFailure
	}

	// Build ancestry proof (branches only; tags don't need one).
	var ancestry []string
	if kind == gitutil.RefBranch {
		if oldCheckpoint, err := gitutil.ReadCheckpoint(c.repoDir, c.ref); err == nil {
			oldBody, err := note.ExtractBody(oldCheckpoint)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(oldBody), "\n")
				if len(lines) >= 2 {
					oldCommit := strings.TrimSpace(lines[1])
					ancestry, err = gitutil.GetCommitChain(c.repoDir, oldCommit, commit)
					if err != nil {
						fmt.Fprintf(os.Stderr, "error: generating ancestry proof: %v\n", err)
						return subcommands.ExitFailure
					}
				}
			}
		}
	}

	// Collect cosignatures from witnesses in parallel.
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
			line, err := witness.Cosign(ctx, w.Endpoint, ancestry, signed)
			ch <- cosigResult{w.PolicyName, line, err}
		}(w)
	}
	cosigned := 0
	for range witnesses {
		r := <-ch
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "warning: witness %s failed: %v\n", r.policyName, r.err)
			continue
		}
		signed = note.AppendSignature(signed, r.cosigLine)
		cosigned++
	}

	// Verify the assembled checkpoint satisfies the policy quorum.
	assembledBody, assembledSigLines, err := note.ParseSignedNote(signed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing assembled checkpoint: %v\n", err)
		return subcommands.ExitFailure
	}
	if err := pol.Verify(assembledBody, assembledSigLines); err != nil {
		fmt.Fprintf(os.Stderr, "error: quorum not satisfied: %v\n", err)
		return subcommands.ExitFailure
	}

	// Store the checkpoint as a git ref.
	if err := gitutil.StoreCheckpoint(c.repoDir, c.ref, signed); err != nil {
		fmt.Fprintf(os.Stderr, "error: storing checkpoint: %v\n", err)
		return subcommands.ExitFailure
	}

	cpRef := "refs/checkpoints/" + strings.TrimPrefix(c.ref, "refs/")
	fmt.Printf("checkpoint stored at %s (%d witness cosignatures)\n", cpRef, cosigned)
	return subcommands.ExitSuccess
}

type verifyCmd struct {
	ref        string
	policyPath string
	repoDir    string
}

func (*verifyCmd) Name() string     { return "verify" }
func (*verifyCmd) Synopsis() string { return "Verify ref checkpoints against a witness policy" }
func (*verifyCmd) Usage() string {
	return `verify [flags]:
  Verify ref checkpoints against a witness policy.

  Verifies checkpoint signatures against the policy and confirms each ref
  still matches the checkpointed commit.

  If --ref is specified, only that ref is verified (it must be listed in
  the policy's ref directives). If --ref is omitted, all refs listed in
  the policy are verified.

  For branches, the local ref must not be ahead of the checkpointed commit.
  For tags, the tag must still point to the exact checkpointed commit.

`
}

func (c *verifyCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ref, "ref", "", "Full ref path to verify (e.g. refs/heads/main); if omitted, verify all refs in the policy")
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *verifyCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
	}

	// Load the policy.
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitFailure
	}

	// Determine which refs to verify.
	var refs []string
	if c.ref != "" {
		if _, err := gitutil.ParseRefKind(c.ref); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid --ref: %v\n", err)
			return subcommands.ExitUsageError
		}
		if !pol.HasRef(c.ref) {
			fmt.Fprintf(os.Stderr, "error: ref %q is not listed in the policy\n", c.ref)
			return subcommands.ExitFailure
		}
		refs = []string{c.ref}
	} else {
		refs = pol.Refs()
		if len(refs) == 0 {
			fmt.Fprintln(os.Stderr, "error: no refs to verify: add ref directives to the policy or use --ref")
			return subcommands.ExitUsageError
		}
	}

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

  2. git-ratchet verify: Verifies all checkpoint refs listed in the
     policy against the witness policy.

  3. Replace ref rejection: Errors if any refs exist under refs/replace/.
     Replace refs allow transparent object substitution, breaking the
     Merkle chain property that git-ratchet relies on.

`
}

func (c *auditCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.policyPath, "policy", "", "Path to witness policy file (required)")
	f.StringVar(&c.repoDir, "repo", ".", "Path to git repository")
}

func (c *auditCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	if c.policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		fmt.Fprint(os.Stderr, c.Usage())
		return subcommands.ExitUsageError
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

	// Phase 2: git-ratchet verify — check all policy refs.
	fmt.Println("Running checkpoint verification...")
	pol, err := policy.Load(c.policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading policy: %v\n", err)
		return subcommands.ExitUsageError
	}
	refs := pol.Refs()
	if len(refs) == 0 {
		fmt.Fprintln(os.Stderr, "FAIL verify: no refs to verify: add ref directives to the policy")
		failed++
	} else {
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

