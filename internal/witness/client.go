// Package witness implements the HTTP client for git-ratchet witness cosigning.
package witness

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Cosign sends a signed checkpoint and its ancestry proof to a witness endpoint
// and returns the cosignature line. The witness verifies the origin signature
// and ancestry, then returns a cosignature.
func Cosign(endpoint string, ancestry []string, signedCheckpoint string) (string, error) {
	url := strings.TrimRight(endpoint, "/") + "/add-checkpoint"

	var parts []string
	if len(ancestry) > 0 {
		parts = append(parts, strings.Join(ancestry, "\n"))
	}
	parts = append(parts, "") // empty line separator
	parts = append(parts, signedCheckpoint)
	reqBody := strings.Join(parts, "\n")

	resp, err := http.Post(url, "text/plain", strings.NewReader(reqBody))
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
	case http.StatusUnprocessableEntity:
		return "", fmt.Errorf("witness rejected checkpoint (invalid ancestry proof): %s", result)
	case http.StatusForbidden:
		return "", fmt.Errorf("witness authorization failed: %s", result)
	default:
		return "", fmt.Errorf("witness HTTP %d: %s", resp.StatusCode, result)
	}
}
