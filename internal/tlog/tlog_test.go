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

package tlog

import (
	"encoding/hex"
	"fmt"
	"testing"
)

// leaves builds n distinct leaf hashes.
func leaves(n int) []Hash {
	out := make([]Hash, n)
	for i := range out {
		out[i] = HashLeaf([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return out
}

// TestEmptyRoot pins the RFC 6962 empty tree hash: SHA-256 of the empty string.
func TestEmptyRoot(t *testing.T) {
	r := EmptyRoot()
	got := hex.EncodeToString(r[:])
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("EmptyRoot() = %s, want %s", got, want)
	}
}

// TestHashLeafEmpty pins the RFC 6962 hash of an empty leaf: SHA-256(0x00).
func TestHashLeafEmpty(t *testing.T) {
	h := HashLeaf(nil)
	got := hex.EncodeToString(h[:])
	want := "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
	if got != want {
		t.Errorf("HashLeaf(nil) = %s, want %s", got, want)
	}
}

// TestRootSingleLeaf checks that a one-leaf tree's root is the leaf itself.
func TestRootSingleLeaf(t *testing.T) {
	l := leaves(1)
	if Root(l) != l[0] {
		t.Error("root of a single-leaf tree should be the leaf hash")
	}
}

// TestInclusionProofRoundTrip generates and verifies an inclusion proof for
// every leaf of every tree size up to 64.
func TestInclusionProofRoundTrip(t *testing.T) {
	for n := 1; n <= 64; n++ {
		l := leaves(n)
		root := Root(l)
		for i := 0; i < n; i++ {
			proof, err := InclusionProof(l, i)
			if err != nil {
				t.Fatalf("n=%d i=%d: InclusionProof: %v", n, i, err)
			}
			if err := VerifyInclusion(l[i], root, proof, i, n); err != nil {
				t.Errorf("n=%d i=%d: VerifyInclusion: %v", n, i, err)
			}
		}
	}
}

// TestInclusionProofWrongLeafFails checks that a proof does not verify against
// a leaf hash it was not generated for.
func TestInclusionProofWrongLeafFails(t *testing.T) {
	const n = 13
	l := leaves(n)
	root := Root(l)
	proof, err := InclusionProof(l, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(l[6], root, proof, 5, n); err == nil {
		t.Error("expected verification to fail for a mismatched leaf hash")
	}
}

// TestInclusionProofTamperedFails checks that flipping a bit in any proof hash
// is detected.
func TestInclusionProofTamperedFails(t *testing.T) {
	const n = 21
	l := leaves(n)
	root := Root(l)
	proof, err := InclusionProof(l, 9)
	if err != nil {
		t.Fatal(err)
	}
	for j := range proof {
		tampered := make([]Hash, len(proof))
		copy(tampered, proof)
		tampered[j][0] ^= 0x01
		if err := VerifyInclusion(l[9], root, tampered, 9, n); err == nil {
			t.Errorf("expected verification to fail with hash %d tampered", j)
		}
	}
}

// TestInclusionProofWrongLengthFails checks that proofs of the wrong length are
// rejected rather than silently truncated.
func TestInclusionProofWrongLengthFails(t *testing.T) {
	const n = 10
	l := leaves(n)
	root := Root(l)
	proof, err := InclusionProof(l, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(l[3], root, proof[:len(proof)-1], 3, n); err == nil {
		t.Error("expected verification to fail for a short proof")
	}
	if err := VerifyInclusion(l[3], root, append(proof, proof[0]), 3, n); err == nil {
		t.Error("expected verification to fail for a long proof")
	}
}

// TestInclusionProofOutOfRange checks index bounds.
func TestInclusionProofOutOfRange(t *testing.T) {
	l := leaves(4)
	if _, err := InclusionProof(l, 4); err == nil {
		t.Error("expected an error for an out-of-range index")
	}
	if _, err := InclusionProof(l, -1); err == nil {
		t.Error("expected an error for a negative index")
	}
}

// TestConsistencyProofRoundTrip generates and verifies a consistency proof for
// every pair of sizes up to 64.
func TestConsistencyProofRoundTrip(t *testing.T) {
	for n := 1; n <= 64; n++ {
		l := leaves(n)
		newRoot := Root(l)
		for m := 0; m <= n; m++ {
			oldRoot := Root(l[:m])
			proof, err := ConsistencyProof(l, m)
			if err != nil {
				t.Fatalf("n=%d m=%d: ConsistencyProof: %v", n, m, err)
			}
			if err := VerifyConsistency(oldRoot, newRoot, proof, m, n); err != nil {
				t.Errorf("n=%d m=%d: VerifyConsistency: %v", n, m, err)
			}
		}
	}
}

// TestConsistencyProofRejectsForkedTree is the property the witness relies on:
// a tree that replaced an existing leaf rather than appending to it must not
// produce a valid consistency proof.
func TestConsistencyProofRejectsForkedTree(t *testing.T) {
	const m = 7
	original := leaves(12)
	oldRoot := Root(original[:m])

	// Fork the log: rewrite leaf 3, which the old tree already committed to.
	forked := make([]Hash, len(original))
	copy(forked, original)
	forked[3] = HashLeaf([]byte("rewritten"))

	proof, err := ConsistencyProof(forked, m)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(oldRoot, Root(forked), proof, m, len(forked)); err == nil {
		t.Error("expected a forked log to fail consistency verification")
	}
}

// TestConsistencyProofTamperedFails checks that flipping a bit in any proof
// hash is detected.
func TestConsistencyProofTamperedFails(t *testing.T) {
	const m, n = 5, 17
	l := leaves(n)
	oldRoot, newRoot := Root(l[:m]), Root(l)
	proof, err := ConsistencyProof(l, m)
	if err != nil {
		t.Fatal(err)
	}
	for j := range proof {
		tampered := make([]Hash, len(proof))
		copy(tampered, proof)
		tampered[j][0] ^= 0x01
		if err := VerifyConsistency(oldRoot, newRoot, tampered, m, n); err == nil {
			t.Errorf("expected verification to fail with hash %d tampered", j)
		}
	}
}

// TestConsistencyProofEqualSize checks the m == n case: no proof, equal roots.
func TestConsistencyProofEqualSize(t *testing.T) {
	l := leaves(9)
	root := Root(l)
	if err := VerifyConsistency(root, root, nil, 9, 9); err != nil {
		t.Errorf("equal roots at equal size should verify: %v", err)
	}
	if err := VerifyConsistency(root, Root(leaves(8)), nil, 9, 9); err == nil {
		t.Error("differing roots at equal size should not verify")
	}
	if err := VerifyConsistency(root, root, []Hash{root}, 9, 9); err == nil {
		t.Error("a non-empty proof at equal size should not verify")
	}
}

// TestConsistencyProofFromEmpty checks that every tree is consistent with the
// empty tree, and that no proof material is expected.
func TestConsistencyProofFromEmpty(t *testing.T) {
	l := leaves(6)
	proof, err := ConsistencyProof(l, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Errorf("proof from size 0 should be empty, got %d hashes", len(proof))
	}
	if err := VerifyConsistency(EmptyRoot(), Root(l), nil, 0, 6); err != nil {
		t.Errorf("consistency from the empty tree should verify: %v", err)
	}
}

// TestConsistencyProofShrinkingRejected checks that a log cannot shrink.
func TestConsistencyProofShrinkingRejected(t *testing.T) {
	l := leaves(10)
	if err := VerifyConsistency(Root(l), Root(l[:4]), nil, 10, 4); err == nil {
		t.Error("expected a shrinking tree to be rejected")
	}
}

// TestConsistencyProofOutOfRange checks size bounds on generation.
func TestConsistencyProofOutOfRange(t *testing.T) {
	l := leaves(4)
	if _, err := ConsistencyProof(l, 5); err == nil {
		t.Error("expected an error when the old size exceeds the tree")
	}
	if _, err := ConsistencyProof(l, -1); err == nil {
		t.Error("expected an error for a negative old size")
	}
}

// TestConsistencyProofEmptyRejected checks that a missing proof cannot stand in
// for a real one when the tree has genuinely grown.
func TestConsistencyProofEmptyRejected(t *testing.T) {
	l := leaves(9)
	if err := VerifyConsistency(Root(l[:5]), Root(l), nil, 5, 9); err == nil {
		t.Error("expected an empty proof to be rejected for a grown tree")
	}
}
