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

// Package tlog implements the RFC 6962 Merkle tree used by git-ratchet's
// transparency-log mode.
//
// Proof generation follows the recursive definitions in RFC 6962 section 2.1
// directly over the full leaf list. git-ratchet logs hold one entry per
// checkpointed ref update, so the leaf list is small enough to keep in memory
// and recompute on demand; there is no need for incremental tree storage.
//
// Proof verification does not require the leaf list, so witnesses can verify a
// consistency proof knowing only the two tree heads.
package tlog

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// HashSize is the length of a node hash in bytes.
const HashSize = sha256.Size

// Hash is a Merkle tree node hash.
type Hash [HashSize]byte

// Prefixes distinguishing leaf hashes from interior node hashes, per
// RFC 6962 section 2.1.
const (
	leafPrefix     = 0x00
	interiorPrefix = 0x01
)

// HashLeaf returns the leaf hash SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// HashChildren returns the interior node hash SHA-256(0x01 || left || right).
func HashChildren(left, right Hash) Hash {
	h := sha256.New()
	h.Write([]byte{interiorPrefix})
	h.Write(left[:])
	h.Write(right[:])
	var out Hash
	copy(out[:], h.Sum(nil))
	return out
}

// EmptyRoot is the Merkle tree hash of an empty log: SHA-256 of the empty
// string, per RFC 6962 section 2.1.
func EmptyRoot() Hash {
	var out Hash
	copy(out[:], sha256.New().Sum(nil))
	return out
}

// splitPoint returns the largest power of two strictly less than n.
// n must be greater than 1.
func splitPoint(n int) int {
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// Root returns the Merkle tree hash of the given leaf hashes.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := splitPoint(len(leaves))
	return HashChildren(Root(leaves[:k]), Root(leaves[k:]))
}

// InclusionProof returns the audit path for the leaf at index i in a tree of
// the given leaves, per RFC 6962 section 2.1.1.
func InclusionProof(leaves []Hash, i int) ([]Hash, error) {
	if i < 0 || i >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range for tree of size %d", i, len(leaves))
	}
	return inclusionProof(leaves, i), nil
}

func inclusionProof(leaves []Hash, i int) []Hash {
	if len(leaves) == 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if i < k {
		return append(inclusionProof(leaves[:k], i), Root(leaves[k:]))
	}
	return append(inclusionProof(leaves[k:], i-k), Root(leaves[:k]))
}

// ConsistencyProof returns the proof that a tree of size m is a prefix of a
// tree of the given leaves, per RFC 6962 section 2.1.2.
//
// A proof from size 0 is empty: every tree is consistent with the empty tree.
func ConsistencyProof(leaves []Hash, m int) ([]Hash, error) {
	n := len(leaves)
	if m < 0 || m > n {
		return nil, fmt.Errorf("old size %d out of range for tree of size %d", m, n)
	}
	if m == 0 || m == n {
		return nil, nil
	}
	return subProof(leaves, m, true), nil
}

func subProof(leaves []Hash, m int, complete bool) []Hash {
	if m == len(leaves) {
		if complete {
			return nil
		}
		return []Hash{Root(leaves)}
	}
	k := splitPoint(len(leaves))
	if m <= k {
		return append(subProof(leaves[:k], m, complete), Root(leaves[k:]))
	}
	return append(subProof(leaves[k:], m-k, false), Root(leaves[:k]))
}

// VerifyInclusion checks that leafHash is the leaf at index i in a tree of
// size n with the given root. It does not need the leaf list.
func VerifyInclusion(leafHash, root Hash, proof []Hash, i, n int) error {
	got, err := RootFromInclusionProof(leafHash, proof, i, n)
	if err != nil {
		return err
	}
	if !bytes.Equal(got[:], root[:]) {
		return fmt.Errorf("inclusion proof does not reproduce root")
	}
	return nil
}

// RootFromInclusionProof recomputes the tree root implied by an inclusion
// proof for the leaf at index i in a tree of size n.
func RootFromInclusionProof(leafHash Hash, proof []Hash, i, n int) (Hash, error) {
	var zero Hash
	if n <= 0 {
		return zero, fmt.Errorf("invalid tree size %d", n)
	}
	if i < 0 || i >= n {
		return zero, fmt.Errorf("leaf index %d out of range for tree of size %d", i, n)
	}

	// The proof splits into an "inner" run, where the leaf's position within
	// the tree decides whether each sibling is on the left or the right, and a
	// "border" run of left-hand siblings above it.
	inner := bits.Len(uint(i ^ (n - 1)))
	border := bits.OnesCount(uint(i) >> uint(inner))
	if len(proof) != inner+border {
		return zero, fmt.Errorf("inclusion proof has %d hashes, want %d", len(proof), inner+border)
	}

	h := leafHash
	for j, p := range proof[:inner] {
		if (i>>uint(j))&1 == 0 {
			h = HashChildren(h, p)
		} else {
			h = HashChildren(p, h)
		}
	}
	for _, p := range proof[inner:] {
		h = HashChildren(p, h)
	}
	return h, nil
}

// VerifyConsistency checks that a tree of size m with root oldRoot is a prefix
// of a tree of size n with root newRoot. It does not need the leaf list, so a
// witness can verify an append-only transition knowing only what it stored and
// what it is being asked to sign.
func VerifyConsistency(oldRoot, newRoot Hash, proof []Hash, m, n int) error {
	if m < 0 || n < 0 {
		return fmt.Errorf("negative tree size")
	}
	if m > n {
		return fmt.Errorf("old size %d exceeds new size %d", m, n)
	}
	if m == n {
		if len(proof) != 0 {
			return fmt.Errorf("consistency proof for unchanged size must be empty")
		}
		if !bytes.Equal(oldRoot[:], newRoot[:]) {
			return fmt.Errorf("tree size unchanged but root differs")
		}
		return nil
	}
	if m == 0 {
		// Every tree is consistent with the empty tree.
		if len(proof) != 0 {
			return fmt.Errorf("consistency proof from size 0 must be empty")
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("empty consistency proof")
	}

	// Walk up from the old tree's last leaf until it is a left child; that is
	// the highest node the two trees can still share.
	node, lastNode := m-1, n-1
	for node&1 == 1 {
		node >>= 1
		lastNode >>= 1
	}

	// When the old size is an exact power of two its root is a complete
	// subtree of the new tree and is not carried in the proof.
	oldSeed, newSeed := oldRoot, oldRoot
	rest := proof
	if node != 0 {
		oldSeed, newSeed = proof[0], proof[0]
		rest = proof[1:]
	}

	for _, p := range rest {
		if lastNode == 0 {
			return fmt.Errorf("consistency proof too long")
		}
		if node&1 == 1 || node == lastNode {
			oldSeed = HashChildren(p, oldSeed)
			newSeed = HashChildren(p, newSeed)
			for node&1 == 0 && node != 0 {
				node >>= 1
				lastNode >>= 1
			}
		} else {
			newSeed = HashChildren(newSeed, p)
		}
		node >>= 1
		lastNode >>= 1
	}

	if lastNode != 0 {
		return fmt.Errorf("consistency proof too short")
	}
	if !bytes.Equal(oldSeed[:], oldRoot[:]) {
		return fmt.Errorf("consistency proof does not reproduce old root")
	}
	if !bytes.Equal(newSeed[:], newRoot[:]) {
		return fmt.Errorf("consistency proof does not reproduce new root")
	}
	return nil
}
