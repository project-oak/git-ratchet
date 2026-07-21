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

// genwitnesskey generates an Ed25519 witness (cosigner) key pair for git-ratchet.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/project-oak/git-ratchet/internal/note"
)

var (
	name = flag.String("name", "", "Key name, e.g. my-witness (required)")
)

func main() {
	flag.Parse()

	if *name == "" {
		flag.Usage()
		log.Fatal("--name is required")
	}

	signer, err := note.GenerateKey(*name, note.Ed25519Cosigner, note.RoleCosigner)
	if err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	seed := base64.StdEncoding.EncodeToString(signer.Seed())

	fmt.Printf("%s\n%s\n", signer.VKey(), seed)
	fmt.Fprintf(os.Stderr, "VKey: %s\n", signer.VKey())
}
