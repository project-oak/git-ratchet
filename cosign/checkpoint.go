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
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	fnote "github.com/transparency-dev/formats/note"
	twitness "github.com/transparency-dev/witness/witness"
	sumdbnote "golang.org/x/mod/sumdb/note"

	inote "github.com/project-oak/git-ratchet/internal/note"
	iwitness "github.com/project-oak/git-ratchet/internal/witness"
)

// answerAddCheckpoint witnesses one add-checkpoint request and returns the response.
//
// Both are message/http: the request arrives as an issue body and the response
// is posted as a comment. The witness is transparency-dev/witness's own HTTP
// handler, so a github-issue witness answers exactly as an HTTP one would --
// same status codes, same Content-Type on a size conflict, same everything.
// Only the wire differs.
func answerAddCheckpoint(ctx context.Context, requestMessage string, witnessKey *inote.Signer, origins map[string]cosignOriginKey, statePath string) (string, error) {
	if statePath == "" {
		return "", fmt.Errorf("--stored-checkpoint is required: a witness with no state cannot ratchet")
	}

	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(requestMessage)))
	if err != nil {
		return "", fmt.Errorf("parsing request message: %w", err)
	}
	req = req.WithContext(ctx)

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

	rec := httptest.NewRecorder()
	twitness.NewAddCheckpointHandler(w.Update).ServeHTTP(rec, req)

	// Without a Content-Length the body runs to the end of the message, so
	// anything the carrier appends -- a trailing newline from a comment box --
	// would be read as part of it.
	resp := rec.Result()
	resp.ContentLength = int64(rec.Body.Len())
	return iwitness.MarshalMessage(resp)
}
