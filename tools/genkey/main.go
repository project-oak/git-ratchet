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

// genkey generates key pairs (origin or witness, Ed25519 or ML-DSA-44) for git-ratchet.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/project-oak/git-ratchet/internal/note"
)

var (
	name = flag.String("name", "", "Name for the generated key")
	role = flag.String("role", "origin", "Key role: origin or witness")
	algo = flag.String("algo", "ed25519", "Key algorithm: ed25519 or ml-dsa")
)

func main() {
	flag.Parse()

	var keyRole note.KeyRole
	switch strings.ToLower(*role) {
	case "origin":
		keyRole = note.RoleOrigin
	case "witness":
		keyRole = note.RoleCosigner
	default:
		log.Fatalf("Invalid role %q: must be origin or witness", *role)
	}

	keyName := *name
	if keyName == "" {
		log.Fatalf("--name must be provided")
	}

	var sigType note.SigType
	switch strings.ToLower(*algo) {
	case "ed25519":
		if keyRole == note.RoleOrigin {
			sigType = note.Ed25519Origin
		} else {
			sigType = note.Ed25519Cosigner
		}
	case "mldsa44":
		sigType = note.MLDSA44
	default:
		log.Fatalf("Invalid algorithm %q: must be ed25519 or mldsa44", *algo)
	}

	signer, err := note.GenerateKey(keyName, sigType, keyRole)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	vkey := signer.VKey()
	seed := base64.StdEncoding.EncodeToString(signer.Seed())

	fmt.Printf("%s\n%s\n", vkey, seed)
	fmt.Fprintf(os.Stderr, "VKey: %s\n", vkey)
}
