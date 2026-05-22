// Command kmsvkey fetches an Ed25519 public key from GCP KMS and prints it
// as a C2SP signed-note verifier key (vkey).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/BenBirt/git-ratchet/internal/note"
)

var (
	kmsKey = flag.String("kms-key", "", "GCP KMS CryptoKeyVersion resource name (required)")
	name   = flag.String("name", "", "Signer name for the vkey (required)")
	role   = flag.String("role", "cosigner", "Key role: 'origin' or 'cosigner'")
)

func main() {
	flag.Parse()

	if *kmsKey == "" || *name == "" {
		fmt.Fprintln(os.Stderr, "error: --kms-key and --name are required")
		flag.Usage()
		os.Exit(1)
	}

	var keyRole note.KeyRole
	switch *role {
	case "origin":
		keyRole = note.RoleOrigin
	case "cosigner":
		keyRole = note.RoleCosigner
	default:
		fmt.Fprintf(os.Stderr, "error: --role must be 'origin' or 'cosigner', got %q\n", *role)
		os.Exit(1)
	}

	ctx := context.Background()
	signer, err := note.NewKMSSigner(ctx, *name, *kmsKey, keyRole)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(signer.VKey())
}
