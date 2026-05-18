// git-ratchet: rollback-resistant Git branch checkpointing.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/BenBirt/git-ratchet/internal/gitutil"
	"github.com/BenBirt/git-ratchet/internal/note"
	"github.com/BenBirt/git-ratchet/internal/policy"
	"github.com/BenBirt/git-ratchet/internal/witness"
)

const usageText = `git-ratchet: rollback-resistant Git branch checkpointing

Usage:
  git-ratchet <command> [flags]

Commands:
  checkpoint    Create a witnessed checkpoint for a branch
  verify        Verify a branch checkpoint against a witness policy

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

func cmdCheckpoint(args []string) {
	fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Create a witnessed checkpoint for a branch.

Signs a checkpoint for the branch HEAD, submits it to the witnesses
in the policy file, collects cosignatures, and stores the cosigned
checkpoint as a Git ref (refs/checkpoints/<branch>).

Usage:
  git-ratchet checkpoint [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to checkpoint (required)")
	commit := fs.String("commit", "", "Commit hash (default: resolve from branch HEAD)")
	policyPath := fs.String("policy", "", "Path to witness policy file (required)")
	keyPath := fs.String("key", "", "Path to origin private key file (required)")
	repoDir := fs.String("repo", ".", "Path to git repository")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *branch == "" || *policyPath == "" || *keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --branch, --policy, and --key are required")
		fs.Usage()
		os.Exit(1)
	}

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
		ref := "refs/heads/" + *branch
		*commit, err = gitutil.ResolveRef(*repoDir, ref)
		if err != nil {
			fatalf("resolving branch HEAD: %v", err)
		}
	}

	// Build the checkpoint body using the log name from the policy.
	body := pol.LogName + " refs/heads/" + *branch + "\n" + *commit + "\n"

	// Sign the checkpoint.
	signed, err := note.Sign(body, signer)
	if err != nil {
		fatalf("signing checkpoint: %v", err)
	}

	// Retrieve previous checkpoint and build ancestry proof.
	var ancestry []string
	if oldCheckpoint, err := gitutil.ReadCheckpoint(*repoDir, *branch); err == nil {
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

	// Collect cosignatures from witnesses in parallel.
	type cosigResult struct {
		policyName string
		cosigLine  string
		err        error
	}
	witnesses := pol.Witnesses()
	ch := make(chan cosigResult, len(witnesses))
	for _, w := range witnesses {
		go func(w *policy.Witness) {
			line, err := witness.Cosign(w.Endpoint, ancestry, signed)
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
	if err := gitutil.StoreCheckpoint(*repoDir, *branch, signed); err != nil {
		fatalf("storing checkpoint: %v", err)
	}

	fmt.Printf("checkpoint stored at refs/checkpoints/%s (%d witness cosignatures)\n", *branch, cosigned)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Verify a branch checkpoint against a witness policy.

Fetches the checkpoint ref for the specified branch, verifies the
origin signature and witness cosignatures against the policy, and
confirms the current branch tip has not moved ahead of the
checkpointed commit.

Usage:
  git-ratchet verify [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to verify (required)")
	policyPath := fs.String("policy", "", "Path to witness policy file (required)")
	repoDir := fs.String("repo", ".", "Path to git repository")
	commit := fs.String("commit", "", "Commit hash to check against checkpoint (default: resolve from branch HEAD)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *branch == "" || *policyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --branch and --policy are required")
		fs.Usage()
		os.Exit(1)
	}

	// Load the policy.
	pol, err := policy.Load(*policyPath)
	if err != nil {
		fatalf("loading policy: %v", err)
	}

	// Read the stored checkpoint.
	checkpoint, err := gitutil.ReadCheckpoint(*repoDir, *branch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: no checkpoint found for branch %q\n", *branch)
		fmt.Fprintf(os.Stderr, "hint: if this repo was cloned, fetch the checkpoint ref with:\n")
		fmt.Fprintf(os.Stderr, "  git fetch origin refs/checkpoints/%s:refs/checkpoints/%s\n", *branch, *branch)
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

	// Determine the commit to check: explicit --commit or branch HEAD.
	var localCommit string
	if *commit != "" {
		localCommit = *commit
	} else {
		ref := "refs/heads/" + *branch
		localCommit, err = gitutil.ResolveRef(*repoDir, ref)
		if err != nil {
			fatalf("resolving branch HEAD: %v", err)
		}
	}

	// localCommit must be an ancestor-or-equal of the checkpointed commit.
	// If it is ahead of the checkpoint, those commits are unwitnessed and
	// could be silently removed — exactly the attack the ratchet guards against.
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

	fmt.Printf("verified: %s @ %s (%d cosignatures)\n",
		strings.TrimSpace(bodyLines[0]), checkpointedCommit[:12], len(sigLines)-1)
}


func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
