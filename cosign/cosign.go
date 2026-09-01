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

// Command cosign answers one add-checkpoint request delivered as a file rather
// than as a POST, and writes the response to stdout. Both are message/http. It
// is the witness half of a github-issue witness.
//
// Usage:
//
//	cosign \
//	    --request request.txt \
//	    --origin-vkeys origins.txt \
//	    --key witness.key \
//	    --stored-checkpoint stored.txt
package main

import (
	"bufio"
	"context"

	"flag"
	"fmt"

	"os"
	"strings"

	"github.com/project-oak/git-ratchet/internal/note"
)

var (
	requestPath          = flag.String("request", "", "Path to add-checkpoint request file (required)")
	originVKeysPath      = flag.String("origin-vkeys", "", "Path to file containing trusted origin vkeys (one per line)")
	storedCheckpointPath = flag.String("stored-checkpoint", "", "Path to this witness's stored checkpoint file (required)")
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

	// This is the same protocol an HTTP witness serves, carried as a file
	// instead of a POST. The witness itself comes from transparency-dev.
	response, err := answerAddCheckpoint(context.Background(), bodyStr, witnessSigner, trustedOrigins, *storedCheckpointPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(response)
}

// cosignOriginKey holds a trusted origin's public key and signature type.
type cosignOriginKey struct {
	// vkey is the line as it appeared in the file. It is handed to
	// transparency-dev/witness, which builds its own verifier from it.
	vkey    string
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
		res[name] = cosignOriginKey{vkey: line, pub: pub, sigType: sigType}
	}
	return res, scanner.Err()
}
