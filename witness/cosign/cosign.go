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

// Command cosign reads an add-checkpoint request from stdin, verifies
// the origin signature and ancestry proof, and writes the cosignature line to
// stdout.
//
// Usage:
//
//	cosign \
//	    --request request.txt \
//	    --origin-vkeys origins.txt \
//	    --key witness-key.pem \
//	    [--stored-checkpoint stored.txt]
package main

import (
	"bufio"

	"flag"
	"fmt"

	"os"
	"strings"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

var (
	requestPath          = flag.String("request", "", "Path to add-checkpoint request file (required)")
	originVKeysPath      = flag.String("origin-vkeys", "", "Path to file containing trusted origin vkeys (one per line)")
	storedCheckpointPath = flag.String("stored-checkpoint", "", "Path to existing cosigned checkpoint file (optional)")
	keyPath              = flag.String("key", "", "Path to witness private key file (required)")
)

func main() {
	flag.Parse()

	if *requestPath == "" {
		fmt.Fprintln(os.Stderr, "error: --request is required")
		os.Exit(1)
	}
	if *originVKeysPath == "" {
		fmt.Fprintln(os.Stderr, "error: --origin-vkeys is required")
		os.Exit(1)
	}
	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "error: --key is required")
		os.Exit(1)
	}

	// Read witness signing key from file.
	witnessSigner, err := note.ReadKeyFile(*keyPath, note.RoleCosigner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading witness key: %v\n", err)
		os.Exit(1)
	}

	// Read trusted origin vkeys.
	trustedOrigins, err := readTrustedOriginsFile(*originVKeysPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading origin vkeys: %v\n", err)
		os.Exit(1)
	}
	if len(trustedOrigins) == 0 {
		fmt.Fprintln(os.Stderr, "error: no trusted origins found in vkeys file")
		os.Exit(1)
	}

	// Read request body from file.
	bodyBytes, err := os.ReadFile(*requestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading request file: %v\n", err)
		os.Exit(1)
	}
	bodyStr := string(bodyBytes)

	// Step 1: Parse the request into ancestry proof and signed note.
	ancestry, signedNote, err := iwitness.ParseAddCheckpointRequest(bodyStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Parse the signed note.
	noteBody, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing signed note: %v\n", err)
		os.Exit(1)
	}
	if len(sigLines) == 0 {
		fmt.Fprintln(os.Stderr, "error: missing origin signature")
		os.Exit(1)
	}

	// Step 3: Verify the origin signature against trusted vkeys.
	originSigName, err := note.SigName(sigLines[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing origin signer name: %v\n", err)
		os.Exit(1)
	}

	originKey, ok := trustedOrigins[originSigName]
	if !ok {
		fmt.Fprintf(os.Stderr, "error: unknown origin: %s\n", originSigName)
		os.Exit(1)
	}

	if err := note.VerifySignature(noteBody, sigLines[0], originKey.pub, originKey.sigType); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid origin signature: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Parse checkpoint body.
	_, ref, newCommit, err := note.ParseCheckpointBody(noteBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Step 5: If stored checkpoint exists, verify ancestry or immutability.
	if *storedCheckpointPath != "" {
		storedData, err := os.ReadFile(*storedCheckpointPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading stored checkpoint: %v\n", err)
			os.Exit(1)
		}
		storedNoteBody, _, err := note.ParseSignedNote(string(storedData))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parsing stored checkpoint: %v\n", err)
			os.Exit(1)
		}
		_, _, storedCommit, err := note.ParseCheckpointBody(storedNoteBody)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parsing stored checkpoint body: %v\n", err)
			os.Exit(1)
		}

		if storedCommit != newCommit {
			refKind, err := gitutil.ParseRefKind(ref)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: unrecognised ref: %v\n", err)
				os.Exit(1)
			}
			if refKind == gitutil.RefTag {
				fmt.Fprintf(os.Stderr, "error: tag checkpoint rejected: stored commit %s differs from submitted commit %s; tags are immutable\n",
					storedCommit, newCommit)
				os.Exit(1)
			}

			// Branch ratchet: ancestry verification required.
			if err := iwitness.VerifyAncestry(ancestry, storedCommit, newCommit, len(newCommit)); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		}
	}

	// Step 6: Generate cosignature.
	cosigLine, err := note.Cosign(signedNote, witnessSigner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: generating cosignature: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(cosigLine)
}

// cosignOriginKey holds a trusted origin's public key and signature type.
type cosignOriginKey struct {
	pub     interface{} // crypto.PublicKey
	sigType note.SigType
}

// readTrustedOriginsFile reads trusted origin vkeys from a file, one per line.
// Lines starting with # and blank lines are ignored.
func readTrustedOriginsFile(path string) (map[string]cosignOriginKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	res := make(map[string]cosignOriginKey)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, sigType, pub, err := note.ParseVKey(line)
		if err != nil {
			return nil, fmt.Errorf("parsing vkey %q: %w", line, err)
		}
		res[name] = cosignOriginKey{pub: pub, sigType: sigType}
	}
	return res, scanner.Err()
}
