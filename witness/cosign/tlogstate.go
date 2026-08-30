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
	"os"
	"path/filepath"
	"strings"
)

// fileState stores a witness's latest cosigned checkpoint in a file, which is
// the shape the decomposed workflow already uses: a caller reads the previous
// checkpoint from somewhere durable, runs the witness, and writes the new one
// back. transparency-dev/witness ships in-memory and Spanner backends; neither
// suits a witness that runs once per submission and then exits.
//
// One file holds one origin, because one invocation serves one submission.
type fileState struct {
	path string
}

func (s *fileState) Init(context.Context) error { return nil }

// Latest returns the stored checkpoint, or nil if there is none. A file naming
// a different origin is an error rather than an empty result: silently
// starting from nothing would hand the submitter a cosignature over a tree
// this witness never ratcheted against.
func (s *fileState) Latest(_ context.Context, origin string) ([]byte, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	stored, _, _ := strings.Cut(string(data), "\n")
	if stored != origin {
		return nil, fmt.Errorf("stored checkpoint in %s is for origin %q, not %q", s.path, stored, origin)
	}
	return data, nil
}

// Update applies f to the stored checkpoint and writes the result back. The
// write is a rename over the target, so a crash leaves the previous checkpoint
// rather than a truncated one.
func (s *fileState) Update(ctx context.Context, origin string, f func([]byte) ([]byte, error)) error {
	current, err := s.Latest(ctx, origin)
	if err != nil {
		return err
	}
	next, err := f(current)
	if err != nil {
		return err
	}
	if next == nil {
		return nil
	}
	// An origin's name has path components of its own, so the directory the
	// state file sits in may not exist on the first accepted submission.
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, next, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
