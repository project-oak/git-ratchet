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

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BenBirt/git-ratchet/internal/note"
)

// writePolicyFile is a test helper that writes a policy string to a temp file.
func writePolicyFile(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "policy.txt")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolicyGitHubIssueWitnessURL(t *testing.T) {
	// Generate keys for the test.
	origin, err := note.GenerateKey("test-log", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	witness1, err := note.GenerateKey("test-witness", note.Ed25519Cosigner, note.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	// Build a policy with a github-issue:// witness URL.
	policyContent := "log " + origin.VKey() + "\n" +
		"witness w1 github-issue://octocat/my-witness " + witness1.VKey() + "\n" +
		"quorum w1\n"

	dir := t.TempDir()
	path := writePolicyFile(t, dir, policyContent)

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify log name.
	if pol.LogName != "test-log" {
		t.Errorf("LogName: got %q, want %q", pol.LogName, "test-log")
	}

	// Verify the witness endpoint is stored verbatim.
	witnesses := pol.Witnesses()
	if len(witnesses) != 1 {
		t.Fatalf("expected 1 witness, got %d", len(witnesses))
	}
	if witnesses[0].Endpoint != "github-issue://octocat/my-witness" {
		t.Errorf("Endpoint: got %q, want %q", witnesses[0].Endpoint, "github-issue://octocat/my-witness")
	}

	// Verify that cosignature verification still works (by key, not by URL).
	body := "test-log refs/heads/main\nabc123\n"
	signed, err := note.Sign(body, origin)
	if err != nil {
		t.Fatal(err)
	}
	cosigLine, err := note.Cosign(signed, witness1)
	if err != nil {
		t.Fatal(err)
	}
	signed = note.AppendSignature(signed, cosigLine)

	_, sigLines, err := note.ParseSignedNote(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Verify(body, sigLines); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

func TestPolicyMixedWitnessURLs(t *testing.T) {
	// Generate keys.
	origin, err := note.GenerateKey("test-log", note.Ed25519Origin, note.RoleOrigin)
	if err != nil {
		t.Fatal(err)
	}
	witness1, err := note.GenerateKey("https-witness", note.Ed25519Cosigner, note.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}
	witness2, err := note.GenerateKey("github-witness", note.Ed25519Cosigner, note.RoleCosigner)
	if err != nil {
		t.Fatal(err)
	}

	// Build a policy with both https:// and github-issue:// witnesses.
	policyContent := "log " + origin.VKey() + "\n" +
		"witness w1 https://witness.example.com " + witness1.VKey() + "\n" +
		"witness w2 github-issue://octocat/my-witness " + witness2.VKey() + "\n" +
		"group both any w1 w2\n" +
		"quorum both\n"

	dir := t.TempDir()
	path := writePolicyFile(t, dir, policyContent)

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify both witnesses are loaded.
	witnesses := pol.Witnesses()
	if len(witnesses) != 2 {
		t.Fatalf("expected 2 witnesses, got %d", len(witnesses))
	}

	// Build a map for easier lookup.
	endpointByName := make(map[string]string)
	for _, w := range witnesses {
		endpointByName[w.PolicyName] = w.Endpoint
	}

	if ep := endpointByName["w1"]; ep != "https://witness.example.com" {
		t.Errorf("w1 Endpoint: got %q, want %q", ep, "https://witness.example.com")
	}
	if ep := endpointByName["w2"]; ep != "github-issue://octocat/my-witness" {
		t.Errorf("w2 Endpoint: got %q, want %q", ep, "github-issue://octocat/my-witness")
	}

	// Verify that cosignature verification works with either witness.
	body := "test-log refs/heads/main\nabc123\n"
	signed, err := note.Sign(body, origin)
	if err != nil {
		t.Fatal(err)
	}

	// Add cosignature from the github-issue witness (w2).
	cosigLine, err := note.Cosign(signed, witness2)
	if err != nil {
		t.Fatal(err)
	}
	signed = note.AppendSignature(signed, cosigLine)

	_, sigLines, err := note.ParseSignedNote(signed)
	if err != nil {
		t.Fatal(err)
	}
	// Quorum is "any" of w1/w2, so one cosignature from w2 should suffice.
	if err := pol.Verify(body, sigLines); err != nil {
		t.Fatalf("Verify with github-issue witness failed: %v", err)
	}
}
