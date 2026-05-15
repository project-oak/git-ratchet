// git-ratchet: rollback-resistant Git branch checkpointing.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nickvidal/git-ratchet/internal/gitutil"
	"github.com/nickvidal/git-ratchet/internal/note"
	"github.com/nickvidal/git-ratchet/internal/policy"
	"github.com/nickvidal/git-ratchet/internal/witness"
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
	origin := fs.String("origin", "", "Origin identifier (default: infer from git remote)")

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

	// Determine origin identifier.
	if *origin == "" {
		url, err := gitutil.RemoteURL(*repoDir)
		if err != nil {
			fatalf("could not infer origin (no git remote); use --origin: %v", err)
		}
		*origin = cleanRemoteURL(url)
	}

	// Build the checkpoint body.
	body := *origin + " refs/heads/" + *branch + "\n" + *commit + "\n"

	// Sign the checkpoint.
	signed, err := note.Sign(body, signer)
	if err != nil {
		fatalf("signing checkpoint: %v", err)
	}

	// Collect cosignatures from witnesses.
	cosigned := 0
	for _, w := range pol.Witnesses {
		cosigLine, err := witness.Cosign(w.Endpoint, signed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: witness %s failed: %v\n", w.Name, err)
			continue
		}
		signed = note.AppendSignature(signed, cosigLine)
		cosigned++
	}

	if cosigned < pol.Quorum {
		fatalf("insufficient cosignatures: got %d, need %d", cosigned, pol.Quorum)
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
confirms the current branch tip matches the checkpointed commit.

Usage:
  git-ratchet verify [flags]

Flags:
`)
		fs.PrintDefaults()
	}

	_ = fs.String("branch", "", "Branch to verify (required)")
	_ = fs.String("policy", "", "Path to witness policy file (required)")

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "error: verify command is not yet implemented")
	os.Exit(1)
}

// cleanRemoteURL normalises a git remote URL into a clean origin string.
// e.g. "https://github.com/example/repo.git" → "github.com/example/repo"
func cleanRemoteURL(u string) string {
	u = strings.TrimSuffix(u, ".git")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	// Handle SSH URLs: git@github.com:example/repo → github.com/example/repo
	if strings.Contains(u, "@") {
		u = u[strings.Index(u, "@")+1:]
		u = strings.Replace(u, ":", "/", 1)
	}
	return u
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
