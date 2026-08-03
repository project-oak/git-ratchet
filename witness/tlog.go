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

package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/project-oak/git-ratchet/internal/note"
	"github.com/project-oak/git-ratchet/internal/tlog"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// handleAddCheckpointTlog implements the C2SP tlog-witness add-checkpoint call.
//
// The witness verifies only that the log grew by appending: it checks the
// origin signature and a Merkle consistency proof from the tree it last
// cosigned to the tree it is being asked to cosign. It never sees the entries,
// so it cannot and does not check what they say about Git refs — that is the
// verifier's job, walking the log.
func (s *Server) handleAddCheckpointTlog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body failed", http.StatusBadRequest)
		return
	}

	req, err := iwitness.ParseTlogRequest(string(bodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	noteBody, sigLines, err := note.ParseSignedNote(req.Note)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse signed note: %v", err), http.StatusBadRequest)
		return
	}
	if len(sigLines) == 0 {
		http.Error(w, "missing origin signature", http.StatusBadRequest)
		return
	}

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

	if err := note.VerifySignature(noteBody, sigLines[0], origin.pub, origin.sigType); err != nil {
		http.Error(w, fmt.Sprintf("invalid origin signature: %v", err), http.StatusForbidden)
		return
	}

	cp, err := tlog.ParseCheckpoint(noteBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The signer must be the log it claims to be. Without this, any origin the
	// witness trusts could advance another origin's stored state.
	if cp.Origin != originSigName {
		http.Error(w, fmt.Sprintf(
			"checkpoint origin %q does not match signer %q", cp.Origin, originSigName),
			http.StatusForbidden)
		return
	}

	if cp.Size == 0 {
		http.Error(w, "refusing to cosign an empty tree", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	stored, initialised := s.trees[cp.Origin]

	if initialised {
		if req.OldSize != stored.Size {
			// Tell the client the size we actually hold so it can regenerate
			// its proof and resubmit in one more round trip.
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, "%s%d\nwitness holds tree size %d, request assumed %d\n",
				iwitness.ConflictSizePrefix, stored.Size, stored.Size, req.OldSize)
			return
		}
		if cp.Size < stored.Size {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusConflict)
			fmt.Fprintf(w, "%s%d\nlog may not shrink: stored size %d, submitted size %d\n",
				iwitness.ConflictSizePrefix, stored.Size, stored.Size, cp.Size)
			return
		}

		storedRoot, err := decodeRoot(stored.Root)
		if err != nil {
			log.Printf("error decoding stored root for %s: %v", cp.Origin, err)
			http.Error(w, "internal server error: corrupt stored state", http.StatusInternalServerError)
			return
		}
		if err := tlog.VerifyConsistency(storedRoot, cp.Root, req.Proof, stored.Size, cp.Size); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else if req.OldSize != 0 {
		// The client believes this witness has state it does not have.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%s0\nwitness holds no tree for origin %s, request assumed size %d\n",
			iwitness.ConflictSizePrefix, cp.Origin, req.OldSize)
		return
	}

	if !initialised || cp.Size > stored.Size {
		s.trees[cp.Origin] = treeState{Size: cp.Size, Root: base64.StdEncoding.EncodeToString(cp.Root[:])}
		if err := s.saveState(); err != nil {
			log.Printf("error saving state file: %v", err)
			http.Error(w, "internal server error: saving state failed", http.StatusInternalServerError)
			return
		}
	}

	cosigLine, err := note.CosignTlogCheckpoint(req.Note, s.witnessKey)
	if err != nil {
		log.Printf("error generating cosignature: %v", err)
		http.Error(w, "internal server error: signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, cosigLine)
}

func decodeRoot(encoded string) (tlog.Hash, error) {
	var h tlog.Hash
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return h, err
	}
	if len(raw) != tlog.HashSize {
		return h, fmt.Errorf("root hash is %d bytes, want %d", len(raw), tlog.HashSize)
	}
	copy(h[:], raw)
	return h, nil
}
