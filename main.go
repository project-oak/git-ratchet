// git-ratchet: rollback-resistant Git branch checkpointing.
//
// git-ratchet creates witnessed checkpoints for Git branches, ensuring
// that branch history can only move forward. Independent witnesses
// cosign checkpoints, making rollback detectable and — with a quorum
// of witnesses — effectively impossible.
package main

import (
	"flag"
	"fmt"
	"os"
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

Signs a checkpoint for the current branch HEAD, submits it to the
witnesses specified in the policy file, collects cosignatures, and
stores the cosigned checkpoint as a Git ref.

Usage:
  git-ratchet checkpoint [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to checkpoint (required)")
	commit := fs.String("commit", "", "Commit hash to checkpoint (defaults to branch HEAD)")
	policy := fs.String("policy", "", "Path to witness policy file (required)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	_ = branch
	_ = commit
	_ = policy

	fmt.Fprintln(os.Stderr, "error: checkpoint command is not yet implemented")
	os.Exit(1)
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Verify a branch checkpoint against a witness policy.

Fetches the checkpoint ref for the specified branch, verifies the
owner signature and witness cosignatures against the policy, and
confirms the current branch tip matches the checkpointed commit.

Usage:
  git-ratchet verify [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	branch := fs.String("branch", "", "Branch to verify (required)")
	policy := fs.String("policy", "", "Path to witness policy file (required)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	_ = branch
	_ = policy

	fmt.Fprintln(os.Stderr, "error: verify command is not yet implemented")
	os.Exit(1)
}
