// Package policy parses git-ratchet witness policy files.
//
// Policy file format:
//
//	origin <vkey>
//	witness <endpoint> <vkey>
//	witness <endpoint> <vkey>
//	quorum <n>
package policy

import (
	"bufio"
	"crypto/ed25519"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nickvidal/git-ratchet/internal/note"
)

// Policy describes the trusted origin and witnesses for a checkpoint.
type Policy struct {
	OriginName string
	OriginKey  ed25519.PublicKey
	Witnesses  []Witness
	Quorum     int
}

// Witness is a witness endpoint and its public key.
type Witness struct {
	Endpoint string
	Name     string
	Key      ed25519.PublicKey
}

// Load reads and parses a policy file.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var p Policy
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "origin":
			if len(fields) != 2 {
				return nil, fmt.Errorf("origin: expected 1 vkey argument")
			}
			name, key, err := note.ParseVKey(fields[1])
			if err != nil {
				return nil, fmt.Errorf("origin vkey: %w", err)
			}
			p.OriginName = name
			p.OriginKey = key
		case "witness":
			if len(fields) != 3 {
				return nil, fmt.Errorf("witness: expected endpoint and vkey")
			}
			name, key, err := note.ParseVKey(fields[2])
			if err != nil {
				return nil, fmt.Errorf("witness vkey: %w", err)
			}
			p.Witnesses = append(p.Witnesses, Witness{
				Endpoint: fields[1],
				Name:     name,
				Key:      key,
			})
		case "quorum":
			if len(fields) != 2 {
				return nil, fmt.Errorf("quorum: expected 1 number")
			}
			p.Quorum, err = strconv.Atoi(fields[1])
			if err != nil {
				return nil, fmt.Errorf("quorum: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown directive: %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if p.OriginKey == nil {
		return nil, fmt.Errorf("policy missing origin key")
	}
	if p.Quorum <= 0 {
		return nil, fmt.Errorf("policy missing or invalid quorum")
	}
	return &p, nil
}
