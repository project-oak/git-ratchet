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

// Package tlog provides the RFC 6962 Merkle tree used by git-ratchet's
// transparency-log mode.
//
// The tree itself comes from github.com/transparency-dev/merkle, maintained by
// the authors of the transparency-log specifications this mode implements.
// Consistency verification in particular is what a witness runs to decide
// whether to cosign, so it is not somewhere to carry a bespoke implementation.
//
// This package is a thin adapter over that library, for two reasons:
//
//   - It works in fixed-size [Hash] values rather than []byte, which makes
//     equality comparisons and struct fields natural for callers.
//   - The library's proof generation reports which tree nodes a proof needs and
//     leaves fetching them to the caller, because it is built for logs whose
//     nodes live in tiled storage. git-ratchet logs are small and held whole in
//     memory, so [nodeSource] resolves those nodes directly from the leaves.
package tlog

import (
	"crypto/sha256"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
)

// HashSize is the length of a node hash in bytes. The library's hasher is
// checked against it at start-up by the assertion below.
const HashSize = sha256.Size

// Hash is a Merkle tree node hash.
type Hash [HashSize]byte

// hasher is the RFC 6962 SHA-256 hasher: leaves are SHA-256(0x00 || data) and
// interior nodes are SHA-256(0x01 || left || right).
var hasher = rfc6962.DefaultHasher

// Guard against HashSize drifting from the configured hasher.
var _ = func() struct{} {
	if got := hasher.Size(); got != HashSize {
		panic(fmt.Sprintf("tlog: hasher emits %d-byte hashes, but HashSize is %d", got, HashSize))
	}
	return struct{}{}
}()

// rangeFactory builds compact ranges, the library's representation of a set of
// perfect subtrees, which is how tree roots are computed here.
var rangeFactory = compact.RangeFactory{Hash: hasher.HashChildren}

// toHash converts a library hash to a fixed-size Hash. It panics if the length
// is wrong, which would mean the hasher was misconfigured rather than that any
// input was bad.
func toHash(b []byte) Hash {
	if len(b) != HashSize {
		panic(fmt.Sprintf("tlog: hash is %d bytes, want %d", len(b), HashSize))
	}
	var h Hash
	copy(h[:], b)
	return h
}

// raw converts a slice of Hash values to the library's representation.
func raw(hashes []Hash) [][]byte {
	out := make([][]byte, len(hashes))
	for i := range hashes {
		out[i] = append([]byte(nil), hashes[i][:]...)
	}
	return out
}

// wrap converts the library's representation back to Hash values.
func wrap(hashes [][]byte) []Hash {
	if len(hashes) == 0 {
		return nil
	}
	out := make([]Hash, len(hashes))
	for i := range hashes {
		out[i] = toHash(hashes[i])
	}
	return out
}

// HashLeaf returns the leaf hash SHA-256(0x00 || data).
func HashLeaf(data []byte) Hash {
	return toHash(hasher.HashLeaf(data))
}

// HashChildren returns the interior node hash SHA-256(0x01 || left || right).
func HashChildren(left, right Hash) Hash {
	return toHash(hasher.HashChildren(left[:], right[:]))
}

// EmptyRoot is the Merkle tree hash of an empty log: SHA-256 of the empty
// string, per RFC 6962 section 2.1.
func EmptyRoot() Hash {
	return toHash(hasher.EmptyRoot())
}

// Root returns the Merkle tree hash of the given leaf hashes.
func Root(leaves []Hash) Hash {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	r := rangeFactory.NewEmptyRange(0)
	for i := range leaves {
		// Append rejects only a leaf that does not extend the range. This
		// range starts empty at zero and is appended to in order, so a failure
		// here would be a bug in this loop rather than bad input.
		if err := r.Append(leaves[i][:], nil); err != nil {
			panic(fmt.Sprintf("tlog: appending leaf %d to an in-order range: %v", i, err))
		}
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		panic(fmt.Sprintf("tlog: computing root of %d leaves: %v", len(leaves), err))
	}
	return toHash(root)
}

// nodeSource resolves tree nodes for proof generation from an in-memory leaf
// list.
type nodeSource []Hash

// hash returns the hash of a perfect subtree node. Proof generation only ever
// asks for nodes whose subtree lies wholly within the tree, so the leaf range
// is always complete.
func (s nodeSource) hash(id compact.NodeID) (Hash, error) {
	begin, end := id.Index<<id.Level, (id.Index+1)<<id.Level
	if end > uint64(len(s)) {
		return Hash{}, fmt.Errorf("node (level %d, index %d) is outside a tree of %d leaves", id.Level, id.Index, len(s))
	}
	return Root(s[begin:end]), nil
}

// fetch resolves every node a proof needs and collapses the ephemeral node, if
// there is one, into the proof hashes.
func (s nodeSource) fetch(nodes proof.Nodes) ([]Hash, error) {
	hashes := make([][]byte, 0, len(nodes.IDs))
	for _, id := range nodes.IDs {
		h, err := s.hash(id)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h[:])
	}
	rehashed, err := nodes.Rehash(hashes, hasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("assembling proof: %w", err)
	}
	return wrap(rehashed), nil
}

// InclusionProof returns the audit path for the leaf at index i in a tree of
// the given leaves.
func InclusionProof(leaves []Hash, i int) ([]Hash, error) {
	if i < 0 || i >= len(leaves) {
		return nil, fmt.Errorf("leaf index %d out of range for tree of size %d", i, len(leaves))
	}
	nodes, err := proof.Inclusion(uint64(i), uint64(len(leaves)))
	if err != nil {
		return nil, err
	}
	return nodeSource(leaves).fetch(nodes)
}

// ConsistencyProof returns the proof that a tree of size m is a prefix of a
// tree of the given leaves.
//
// A proof from size 0 is empty: every tree is consistent with the empty tree.
// So is a proof to the same size.
func ConsistencyProof(leaves []Hash, m int) ([]Hash, error) {
	n := len(leaves)
	if m < 0 || m > n {
		return nil, fmt.Errorf("old size %d out of range for tree of size %d", m, n)
	}
	if m == 0 || m == n {
		return nil, nil
	}
	nodes, err := proof.Consistency(uint64(m), uint64(n))
	if err != nil {
		return nil, err
	}
	return nodeSource(leaves).fetch(nodes)
}

// VerifyInclusion checks that leafHash is the leaf at index i in a tree of
// size n with the given root. It does not need the leaf list.
func VerifyInclusion(leafHash, root Hash, p []Hash, i, n int) error {
	if n <= 0 {
		return fmt.Errorf("invalid tree size %d", n)
	}
	if i < 0 || i >= n {
		return fmt.Errorf("leaf index %d out of range for tree of size %d", i, n)
	}
	return proof.VerifyInclusion(hasher, uint64(i), uint64(n), leafHash[:], raw(p), root[:])
}

// RootFromInclusionProof recomputes the tree root implied by an inclusion
// proof for the leaf at index i in a tree of size n.
func RootFromInclusionProof(leafHash Hash, p []Hash, i, n int) (Hash, error) {
	if n <= 0 {
		return Hash{}, fmt.Errorf("invalid tree size %d", n)
	}
	if i < 0 || i >= n {
		return Hash{}, fmt.Errorf("leaf index %d out of range for tree of size %d", i, n)
	}
	root, err := proof.RootFromInclusionProof(hasher, uint64(i), uint64(n), leafHash[:], raw(p))
	if err != nil {
		return Hash{}, err
	}
	return toHash(root), nil
}

// VerifyConsistency checks that a tree of size m with root oldRoot is a prefix
// of a tree of size n with root newRoot. It does not need the leaf list, so a
// witness can verify an append-only transition knowing only what it stored and
// what it is being asked to sign.
func VerifyConsistency(oldRoot, newRoot Hash, p []Hash, m, n int) error {
	if m < 0 || n < 0 {
		return fmt.Errorf("negative tree size")
	}
	return proof.VerifyConsistency(hasher, uint64(m), uint64(n), raw(p), oldRoot[:], newRoot[:])
}
