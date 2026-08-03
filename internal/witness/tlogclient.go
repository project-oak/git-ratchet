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

package witness

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/project-oak/git-ratchet/internal/tlog"
)

// ConflictSizePrefix marks the first line of a 409 response body, which
// carries the tree size the witness actually holds.
//
// The tlog-witness protocol expects a stale client to recover by regenerating
// its proof from the witness's real size and resubmitting. Reporting the size
// in a machine-readable form is what makes that single-round recovery
// possible.
const ConflictSizePrefix = "old "

// ProofFunc returns a consistency proof from oldSize to the size of the
// checkpoint being submitted.
type ProofFunc func(oldSize int) ([]tlog.Hash, error)

// CosignTlog submits a signed tlog-checkpoint to a witness and returns the
// cosignature line.
//
// If the witness reports a different stored size (HTTP 409), CosignTlog
// regenerates the consistency proof from the size the witness actually holds
// and retries once. This is the conflict recovery that the git-checkpoint
// protocol sidesteps by sending a commit chain that spans any gap; with a
// Merkle log the proof is anchored to a specific size, so the round trip is
// unavoidable.
func CosignTlog(ctx context.Context, endpoint string, oldSize int, proofFor ProofFunc, signedNote string) (string, error) {
	cosig, conflictSize, err := postTlog(ctx, endpoint, oldSize, proofFor, signedNote)
	if err == nil {
		return cosig, nil
	}
	if conflictSize < 0 || conflictSize == oldSize {
		return "", err
	}

	cosig, _, retryErr := postTlog(ctx, endpoint, conflictSize, proofFor, signedNote)
	if retryErr != nil {
		return "", fmt.Errorf("retry from witness size %d: %w", conflictSize, retryErr)
	}
	return cosig, nil
}

// postTlog performs one add-checkpoint round trip. When the witness reports a
// conflicting size, it is returned alongside the error; otherwise the returned
// size is -1.
func postTlog(ctx context.Context, endpoint string, oldSize int, proofFor ProofFunc, signedNote string) (string, int, error) {
	proof, err := proofFor(oldSize)
	if err != nil {
		return "", -1, fmt.Errorf("generating consistency proof from size %d: %w", oldSize, err)
	}

	url := strings.TrimRight(endpoint, "/") + "/add-checkpoint"
	body := FormatTlogRequest(oldSize, proof, signedNote)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return "", -1, fmt.Errorf("building request for witness %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", -1, fmt.Errorf("contacting witness %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", -1, fmt.Errorf("reading witness response: %w", err)
	}
	result := strings.TrimSpace(string(respBody))

	switch resp.StatusCode {
	case http.StatusOK:
		return result, -1, nil
	case http.StatusConflict:
		return "", parseConflictSize(result), &RejectionError{StatusCode: resp.StatusCode, Detail: result}
	case http.StatusUnprocessableEntity, http.StatusForbidden:
		return "", -1, &RejectionError{StatusCode: resp.StatusCode, Detail: result}
	default:
		return "", -1, fmt.Errorf("witness HTTP %d: %s", resp.StatusCode, result)
	}
}

// parseConflictSize extracts the witness's stored tree size from a 409 body,
// returning -1 if it is not reported in the expected form.
func parseConflictSize(body string) int {
	first, _, _ := strings.Cut(body, "\n")
	sizeStr, ok := strings.CutPrefix(strings.TrimSpace(first), ConflictSizePrefix)
	if !ok {
		return -1
	}
	size, err := strconv.Atoi(strings.TrimSpace(sizeStr))
	if err != nil || size < 0 {
		return -1
	}
	return size
}
