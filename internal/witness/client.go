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

// Package witness implements the HTTP client for git-ratchet witness cosigning.
package witness

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RejectionError indicates the witness actively rejected the checkpoint.
// This is fundamentally different from a transient failure (timeout, 5xx):
// a rejection means the witness inspected the checkpoint and determined it
// is invalid — for example, the ancestry proof failed (HTTP 422), which is
// the strongest signal that a rollback may be in progress.
//
// Callers should treat RejectionError as a hard, non-skippable failure.
type RejectionError struct {
	// StatusCode is the HTTP status returned by the witness.
	StatusCode int
	// Detail is the body text returned by the witness.
	Detail string
}

func (e *RejectionError) Error() string {
	switch e.StatusCode {
	case http.StatusUnprocessableEntity:
		return fmt.Sprintf("witness rejected checkpoint (invalid ancestry proof): %s", e.Detail)
	case http.StatusConflict:
		return fmt.Sprintf("witness rejected checkpoint (conflict): %s", e.Detail)
	case http.StatusForbidden:
		return fmt.Sprintf("witness authorization failed: %s", e.Detail)
	default:
		return fmt.Sprintf("witness rejected checkpoint (HTTP %d): %s", e.StatusCode, e.Detail)
	}
}

// Cosign sends a signed checkpoint and its ancestry proof to a witness endpoint
// and returns the cosignature line. The witness verifies the origin signature
// and ancestry, then returns a cosignature.
//
// The caller should pass a context with an appropriate deadline; Cosign will
// cancel the HTTP request and return an error if the context expires.
//
// Cosign returns a *RejectionError when the witness actively rejects the
// checkpoint (HTTP 409, 422, or 403). Callers must not silently skip these
// errors.
func Cosign(ctx context.Context, endpoint string, ancestry []string, signedCheckpoint string) (string, error) {
	url := strings.TrimRight(endpoint, "/") + "/add-checkpoint"

	var parts []string
	if len(ancestry) > 0 {
		parts = append(parts, strings.Join(ancestry, "\n"))
	}
	parts = append(parts, "") // empty line separator
	parts = append(parts, signedCheckpoint)
	reqBody := strings.Join(parts, "\n")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("building request for witness %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("contacting witness %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading witness response: %w", err)
	}
	result := strings.TrimSpace(string(body))

	switch resp.StatusCode {
	case http.StatusOK:
		return result, nil
	case http.StatusUnprocessableEntity, http.StatusConflict, http.StatusForbidden:
		return "", &RejectionError{StatusCode: resp.StatusCode, Detail: result}
	default:
		return "", fmt.Errorf("witness HTTP %d: %s", resp.StatusCode, result)
	}
}
