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

// Command kmsvkey fetches an Ed25519 public key from GCP KMS and prints it
// as a C2SP signed-note verifier key (vkey).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/project-oak/git-ratchet/internal/note"
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
