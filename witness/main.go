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

// Package main implements a C2SP-aligned Git Checkpoint Witness HTTP server.
package main

import (
	"bufio"
	"context"
	"crypto"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/project-oak/git-ratchet/internal/gitutil"
	"github.com/project-oak/git-ratchet/internal/note"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// trustedOrigin holds a trusted origin's public key and signature type.
type trustedOrigin struct {
	pub     crypto.PublicKey
	sigType note.SigType
}

type Server struct {
	witnessKey     *note.Signer
	trustedOrigins map[string]trustedOrigin
	stateFile      string
	mu             sync.RWMutex
	commits        map[string]string // branch key -> commit hash
}

var (
	addr        = flag.String("addr", ":8080", "Address to listen on")
	keyPath     = flag.String("key", "", "Path to witness private key file (required unless --kms-key is set)")
	kmsKeyFlag  = flag.String("kms-key", "", "GCP KMS key resource name for remote cosigning (alternative to --key)")
	witnessName = flag.String("name", "", "Witness signer name (required with --kms-key; ignored with --key)")
	originsFlag = flag.String("origins", "", "Comma-separated list of trusted origin verifier keys (vkeys)")
	originsFile = flag.String("origins-file", "", "Path to file containing trusted origin verifier keys (one per line)")
	stateFile   = flag.String("state-file", "", "Path to JSON file to persist witness state")
)

func main() {
	flag.Parse()

	if *keyPath == "" && *kmsKeyFlag == "" {
		log.Fatalf("error: one of --key or --kms-key is required")
	}
	if *keyPath != "" && *kmsKeyFlag != "" {
		log.Fatalf("error: --key and --kms-key are mutually exclusive")
	}

	// Read witness signer key (cosigner role).
	var wSigner *note.Signer
	var err error
	if *kmsKeyFlag != "" {
		if *witnessName == "" {
			log.Fatalf("error: --name is required when using --kms-key")
		}
		wSigner, err = note.NewKMSSigner(context.Background(), *witnessName, *kmsKeyFlag, note.RoleCosigner)
		if err != nil {
			log.Fatalf("failed to create KMS signer: %v", err)
		}
	} else {
		wSigner, err = note.ReadKeyFile(*keyPath, note.RoleCosigner)
		if err != nil {
			log.Fatalf("failed to read witness key: %v", err)
		}
	}

	// Accumulate trusted origins.
	var rawOrigins []string
	if *originsFlag != "" {
		rawOrigins = append(rawOrigins, strings.Split(*originsFlag, ",")...)
	}
	if *originsFile != "" {
		fileOrigins, err := readOriginsFile(*originsFile)
		if err != nil {
			log.Fatalf("failed to read origins file: %v", err)
		}
		rawOrigins = append(rawOrigins, fileOrigins...)
	}

	trustedOrig, err := parseOrigins(rawOrigins)
	if err != nil {
		log.Fatalf("failed to parse trusted origins: %v", err)
	}

	srv := &Server{
		witnessKey:     wSigner,
		trustedOrigins: trustedOrig,
		stateFile:      *stateFile,
		commits:        make(map[string]string),
	}

	// Load stored state if any.
	if err := srv.loadState(); err != nil {
		log.Fatalf("failed to load state file: %v", err)
	}

	http.HandleFunc("/add-checkpoint", srv.handleAddCheckpoint)

	log.Printf("Starting witness %q on %s", wSigner.Name, *addr)
	if len(srv.trustedOrigins) > 0 {
		log.Printf("Trusted origins: %d configured", len(srv.trustedOrigins))
	} else {
		log.Printf("WARNING: no trusted origins configured. All submissions will fail with 404!")
	}

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) handleAddCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body failed", http.StatusBadRequest)
		return
	}
	bodyStr := string(bodyBytes)

	// Split body into ancestry proof and signed note.
	ancestry, signedNote, err := iwitness.ParseAddCheckpointRequest(bodyStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Parse checkpoint signed note.
	noteBody, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse signed note: %v", err), http.StatusBadRequest)
		return
	}
	if len(sigLines) == 0 {
		http.Error(w, "missing origin signature", http.StatusBadRequest)
		return
	}

	// Extract origin signer name and lookup key.
	originSigName, err := note.SigName(sigLines[0])
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse origin signer name: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	origin, ok := s.trustedOrigins[originSigName]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, fmt.Sprintf("unauthorized origin: %s", originSigName), http.StatusNotFound)
		return
	}

	// Verify origin signature.
	if err := note.VerifySignature(noteBody, sigLines[0], origin.pub, origin.sigType); err != nil {
		http.Error(w, fmt.Sprintf("invalid origin signature: %v", err), http.StatusForbidden)
		return
	}

	// Parse checkpoint body.
	cpOrigin, ref, newCommit, err := note.ParseCheckpointBody(noteBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	stateKey := cpOrigin + " " + ref

	s.mu.Lock()
	defer s.mu.Unlock()

	storedCommit := s.commits[stateKey]

	if storedCommit != "" && newCommit != storedCommit {
		refKind, err := gitutil.ParseRefKind(ref)
		if err != nil {
			http.Error(w, fmt.Sprintf("unrecognised ref: %v", err), http.StatusBadRequest)
			return
		}
		if refKind == gitutil.RefTag {
			// Tag pinning: refuse any change to the stored commit.
			http.Error(w, fmt.Sprintf(
				"tag checkpoint rejected: stored commit %s differs from submitted commit %s; tags are immutable",
				storedCommit, newCommit), http.StatusConflict)
			return
		}

		// Branch ratchet: ancestry verification required.
		if err := iwitness.VerifyAncestry(ancestry, storedCommit, newCommit, len(newCommit)); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Update stored state if it's empty, or if verification succeeded and newCommit != storedCommit.
	if storedCommit != newCommit {
		s.commits[stateKey] = newCommit
		if err := s.saveState(); err != nil {
			log.Printf("error saving state file: %v", err)
			http.Error(w, "internal server error: saving state failed", http.StatusInternalServerError)
			return
		}
	}

	// Cosign checkpoint.
	cosigLine, err := note.Cosign(signedNote, s.witnessKey)
	if err != nil {
		log.Printf("error generating cosignature: %v", err)
		http.Error(w, "internal server error: signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, cosigLine)
}

func (s *Server) loadState() error {
	if s.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.stateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.commits)
}

func (s *Server) saveState() error {
	if s.stateFile == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.commits, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.stateFile)
}

func readOriginsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vkeys []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		vkeys = append(vkeys, line)
	}
	return vkeys, scanner.Err()
}

func parseOrigins(origins []string) (map[string]trustedOrigin, error) {
	res := make(map[string]trustedOrigin)
	for _, vkey := range origins {
		vkey = strings.TrimSpace(vkey)
		if vkey == "" {
			continue
		}
		name, sigType, pub, err := note.ParseVKey(vkey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trusted origin vkey %q: %w", vkey, err)
		}
		res[name] = trustedOrigin{pub: pub, sigType: sigType}
	}
	return res, nil
}
