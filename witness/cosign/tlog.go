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
	"context"
	"fmt"
	"strings"

	fnote "github.com/transparency-dev/formats/note"
	twitness "github.com/transparency-dev/witness/witness"
	sumdbnote "golang.org/x/mod/sumdb/note"

	inote "github.com/project-oak/git-ratchet/internal/note"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// cosignTlog witnesses a tlog-checkpoint submitted as a file rather than as a
// POST, which is what the GitHub Issue transport carries.
//
// The witness itself is transparency-dev/witness. Its Update applies the whole
// of tlog-witness — signature, origin, size ordering, root hash at equal sizes,
// consistency proof — and returns the cosignature lines, so what is here is the
// transport and the storage and nothing about the protocol.
func cosignTlog(ctx context.Context, requestBody string, witnessKey *inote.Signer, origins map[string]cosignOriginKey, statePath string) (string, error) {
	if statePath == "" {
		return "", fmt.Errorf("--stored-checkpoint is required: a witness with no state cannot ratchet")
	}

	req, err := iwitness.ParseTlogRequest(requestBody)
	if err != nil {
		return "", err
	}

	signer, err := inote.TlogCosigner(witnessKey)
	if err != nil {
		return "", fmt.Errorf("witness key: %w", err)
	}

	w, err := twitness.New(ctx, twitness.Opts{
		Persistence: &fileState{path: statePath},
		Signers:     []sumdbnote.Signer{signer},
		VerifierForLog: func(_ context.Context, origin string) (sumdbnote.Verifier, bool, error) {
			o, ok := origins[origin]
			if !ok {
				return nil, false, nil
			}
			v, err := fnote.NewVerifier(o.vkey)
			if err != nil {
				return nil, false, fmt.Errorf("trusted origin %q has an unusable vkey: %w", origin, err)
			}
			return v, true, nil
		},
	})
	if err != nil {
		return "", fmt.Errorf("creating witness: %w", err)
	}

	proof := make([][]byte, 0, len(req.Proof))
	for _, h := range req.Proof {
		proof = append(proof, h[:])
	}

	sigs, size, err := w.Update(ctx, req.OldSize, []byte(req.Note), proof)
	if err != nil {
		// A stale submission is recoverable: the size the witness holds is
		// what the client needs to regenerate its proof from.
		if size != req.OldSize {
			return "", fmt.Errorf("%w (witness holds tree size %d)", err, size)
		}
		return "", err
	}
	return strings.TrimSpace(string(sigs)), nil
}
