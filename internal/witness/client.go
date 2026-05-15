// Package witness implements the HTTP client for git-ratchet witness cosigning.
package witness

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Cosign sends a signed checkpoint to a witness endpoint and returns the
// cosignature line. The witness verifies the origin signature and ancestry,
// then returns a cosignature.
func Cosign(endpoint, signedCheckpoint string) (string, error) {
	url := strings.TrimRight(endpoint, "/") + "/cosign"
	resp, err := http.Post(url, "text/plain", strings.NewReader(signedCheckpoint))
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
	case http.StatusConflict:
		return "", fmt.Errorf("witness state mismatch (stored commit: %s)", result)
	case http.StatusUnprocessableEntity:
		return "", fmt.Errorf("witness rejected checkpoint: %s", result)
	case http.StatusForbidden:
		return "", fmt.Errorf("witness authorization failed: %s", result)
	default:
		return "", fmt.Errorf("witness HTTP %d: %s", resp.StatusCode, result)
	}
}
