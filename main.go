// git-ratchet: rollback-resistant Git branch checkpointing.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BenBirt/git-ratchet/internal/gitutil"
	"github.com/BenBirt/git-ratchet/internal/note"
	"github.com/BenBirt/git-ratchet/internal/policy"
	"github.com/BenBirt/git-ratchet/internal/witness"
)

const usageText = `git-ratchet: rollback-resistant Git ref checkpointing

Usage:
  git-ratchet <command> [flags]

Commands:
  checkpoint    Create a witnessed checkpoint for a branch or tag
  verify        Verify a ref checkpoint against a witness policy

Use "git-ratchet <command> --help" for more information about a command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "checkpoint":
		cmdCheckpoint(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "help", "--help", "-h":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}
}

// resolveRef parses the --branch and --tag flags and returns the full ref
// path and its kind. It exits with an error if both or neither flag is set.
func resolveRef(branch, tag string) (ref string, kind gitutil.RefKind) {
	if (branch == "" && tag == "") || (branch != "" && tag != "") {
		fmt.Fprintln(os.Stderr, "error: exactly one of --branch or --tag is required")
		os.Exit(1)
	}
	if tag != "" {
		return "refs/tags/" + tag, gitutil.RefTag
	}
	return "refs/heads/" + branch, gitutil.RefBranch
}

func cmdCheckpoint(args []string) {
	fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Create a witnessed checkpoint for a branch or tag.

Signs a checkpoint for the ref, submits it to the witnesses in the policy
file, collects cosignatures, and stores the cosigned checkpoint as a Git
ref (refs/checkpoints/heads/<branch> or refs/checkpoints/tags/<tag>).

For branches, witnesses enforce a forward-only ratchet: the new commit
must be a descendant of the previously witnessed commit.

For tags, witnesses enforce immutability: the tag is pinned to the first
commit it is witnessed at, and any subsequent checkpoint with a different
commit is rejected.

Usage:
  git-ratchet checkpoint [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to checkpoint (mutually exclusive with --tag)")
	tag := fs.String("tag", "", "Tag to checkpoint (mutually exclusive with --branch)")
	commit := fs.String("commit", "", "Commit hash (default: resolve from ref)")
	policyPath := fs.String("policy", "", "Path to witness policy file (required)")
	keyPath := fs.String("key", "", "Path to origin private key file (required)")
	repoDir := fs.String("repo", ".", "Path to git repository")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *policyPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy and --key are required")
		fs.Usage()
		os.Exit(1)
	}

	ref, kind := resolveRef(*branch, *tag)

	// Load the origin signing key.
	signer, err := note.ReadKeyFile(*keyPath)
	if err != nil {
		fatalf("loading key: %v", err)
	}

	// Load the policy.
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fatalf("loading policy: %v", err)
	}

	// Resolve commit hash if not specified.
	if *commit == "" {
		*commit, err = gitutil.ResolveRef(*repoDir, ref)
		if err != nil {
			fatalf("resolving ref: %v", err)
		}
	}

	// Build the checkpoint body using the log name from the policy.
	body := pol.LogName + " " + ref + "\n" + *commit + "\n"

	// Sign the checkpoint.
	signed, err := note.Sign(body, signer)
	if err != nil {
		fatalf("signing checkpoint: %v", err)
	}

	// Build ancestry proof (branches only; tags don't need one).
	var ancestry []string
	if kind == gitutil.RefBranch {
		if oldCheckpoint, err := gitutil.ReadCheckpoint(*repoDir, ref); err == nil {
			oldBody, err := note.ExtractBody(oldCheckpoint)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(oldBody), "\n")
				if len(lines) >= 2 {
					oldCommit := strings.TrimSpace(lines[1])
					ancestry, err = gitutil.GetCommitChain(*repoDir, oldCommit, *commit)
					if err != nil {
						fatalf("failed to generate ancestry proof: %v", err)
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
		fatalf("parsing assembled checkpoint: %v", err)
	}
	if err := pol.Verify(assembledBody, assembledSigLines); err != nil {
		fatalf("checkpoint does not meet policy quorum: %v", err)
	}

	// Store the checkpoint as a git ref.
	if err := gitutil.StoreCheckpoint(*repoDir, ref, signed); err != nil {
		fatalf("storing checkpoint: %v", err)
	}

	cpRef := "refs/checkpoints/" + strings.TrimPrefix(ref, "refs/")
	fmt.Printf("checkpoint stored at %s (%d witness cosignatures)\n", cpRef, cosigned)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Verify a ref checkpoint against a witness policy.

Fetches the checkpoint ref, verifies the origin signature and witness
cosignatures against the policy, and confirms the current ref still
matches the checkpointed commit.

For branches, the local HEAD must not be ahead of the checkpointed commit.
For tags, the tag must still point to the exact checkpointed commit.

Usage:
  git-ratchet verify [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to verify (mutually exclusive with --tag)")
	tag := fs.String("tag", "", "Tag to verify (mutually exclusive with --branch)")
	policyPath := fs.String("policy", "", "Path to witness policy file (required)")
	repoDir := fs.String("repo", ".", "Path to git repository")
	commit := fs.String("commit", "", "Commit hash to check against checkpoint (default: resolve from ref)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --policy is required")
		fs.Usage()
		os.Exit(1)
	}

	ref, kind := resolveRef(*branch, *tag)

	// Load the policy.
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fatalf("loading policy: %v", err)
	}

	// Read the stored checkpoint.
	checkpoint, err := gitutil.ReadCheckpoint(*repoDir, ref)
	if err != nil {
		cpRef := "refs/checkpoints/" + strings.TrimPrefix(ref, "refs/")
		fmt.Fprintf(os.Stderr, "error: no checkpoint found for ref %q\n", ref)
		fmt.Fprintf(os.Stderr, "hint: if this repo was cloned, fetch the checkpoint ref with:\n")
		fmt.Fprintf(os.Stderr, "  git fetch origin %s:%s\n", cpRef, cpRef)
		os.Exit(1)
	}

	// Parse the signed note.
	body, sigLines, err := note.ParseSignedNote(checkpoint)
	if err != nil {
		fatalf("parsing checkpoint: %v", err)
	}

	// Verify origin signature and witness cosignatures.
	if err := pol.Verify(body, sigLines); err != nil {
		fatalf("checkpoint verification failed: %v", err)
	}

	// Extract the checkpointed commit hash from the note body.
	bodyLines := strings.Split(strings.TrimSpace(body), "\n")
	if len(bodyLines) < 2 {
		fatalf("malformed checkpoint body")
	}
	checkpointedCommit := strings.TrimSpace(bodyLines[1])

	// Determine the commit to check: explicit --commit or resolve from ref.
	var localCommit string
	if *commit != "" {
		localCommit = *commit
	} else {
		localCommit, err = gitutil.ResolveRef(*repoDir, ref)
		if err != nil {
			fatalf("resolving ref: %v", err)
		}
	}

	if kind == gitutil.RefTag {
		// Tag pinning: current commit must exactly match checkpoint.
		if localCommit != checkpointedCommit {
			fmt.Fprintf(os.Stderr, "error: tag does not match checkpoint\n")
			fmt.Fprintf(os.Stderr, "  current commit:       %s\n", localCommit)
			fmt.Fprintf(os.Stderr, "  checkpointed commit:  %s\n", checkpointedCommit)
			fmt.Fprintf(os.Stderr, "The tag has been moved since it was witnessed.\n")
			os.Exit(1)
		}
	} else {
		// Branch ratchet: local commit must be ancestor-or-equal of the
		// checkpointed commit. If it is ahead, those commits are
		// unwitnessed and could be silently removed.
		ok, err := gitutil.IsAncestor(*repoDir, localCommit, checkpointedCommit)
		if err != nil {
			fatalf("checking ancestry: %v", err)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "error: local commit is ahead of the last witnessed checkpoint\n")
			fmt.Fprintf(os.Stderr, "  local commit:         %s\n", localCommit)
			fmt.Fprintf(os.Stderr, "  checkpointed commit:  %s\n", checkpointedCommit)
			fmt.Fprintf(os.Stderr, "Commits after the checkpoint have not been witnessed and could be\n")
			fmt.Fprintf(os.Stderr, "silently removed. Run \"git-ratchet checkpoint\" to extend the ratchet.\n")
			os.Exit(1)
		}
	}

	fmt.Printf("verified: %s @ %s (%d cosignatures)\n",
		strings.TrimSpace(bodyLines[0]), checkpointedCommit[:12], len(sigLines)-1)
}


func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
