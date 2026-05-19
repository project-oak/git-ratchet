// Package policy parses git-ratchet witness policy files.
//
// Policy file format follows the C2SP tlog-policy specification:
//
//	log <vkey>
//
//	witness <name> [<url>] <vkey>
//	witness <name> [<url>] <vkey>
//
//	group <name> <n|any|all> <member> [<member>...]
//
//	quorum <name|none>
//
// Each witness and group has a local policy name used only for group
// membership and quorum references.  The signer name embedded in the vkey
// is used when matching cosignature lines in a note.
package policy

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/BenBirt/git-ratchet/internal/note"
)

// Witness is a single trusted cosigner.
type Witness struct {
	PolicyName string           // local label in the policy file
	SignerName string            // signer name embedded in the vkey; used to match cosig lines
	Endpoint   string           // HTTP endpoint; empty for offline-only verification
	Key        ed25519.PublicKey
	keyHash    [4]byte // SHA-256(signerName+"\n"+0x04+pub)[:4] per tlog-cosignature
}

// Group is a named threshold set of witnesses and/or sub-groups.
// A leaf group has Witness non-nil and no Members.
// A non-leaf group has Members and Threshold.
type Group struct {
	Threshold int
	Members   []*Group
	Witness   *Witness // non-nil only for leaf nodes
}

// satisfied reports whether this group's threshold is met given the set of
// signer names that have produced valid cosignatures.
func (g *Group) satisfied(witnessed map[string]bool) bool {
	if g.Witness != nil {
		return witnessed[g.Witness.SignerName]
	}
	count := 0
	for _, m := range g.Members {
		if m.satisfied(witnessed) {
			count++
		}
	}
	return count >= g.Threshold
}

// Policy is the parsed tlog-policy.
type Policy struct {
	LogName    string
	LogKey     ed25519.PublicKey
	logKeyHash [4]byte
	witnesses  map[string]*Witness // keyed by PolicyName
	// groups contains one entry per witness (implicit singleton) and per group directive.
	groups    map[string]*Group
	quorum    *Group // nil means "quorum none"
	quorumSet bool
}

// Witnesses returns all witnesses defined in the policy.
// The order is unspecified.
func (p *Policy) Witnesses() []*Witness {
	ws := make([]*Witness, 0, len(p.witnesses))
	for _, w := range p.witnesses {
		ws = append(ws, w)
	}
	return ws
}

// Load reads and parses a policy file.
func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	p := &Policy{
		witnesses: make(map[string]*Witness),
		groups:    make(map[string]*Group),
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		switch fields[0] {
		case "log":
			if len(fields) != 2 {
				return nil, fmt.Errorf("log: expected 1 vkey argument")
			}
			name, keyType, key, err := note.ParseVKey(fields[1])
			if err != nil {
				return nil, fmt.Errorf("log vkey: %w", err)
			}
			if keyType != note.Ed25519Origin {
				return nil, fmt.Errorf("log vkey must use origin key type (0x%02x), got 0x%02x", note.Ed25519Origin, keyType)
			}
			p.LogName = name
			p.LogKey = key
			p.logKeyHash = note.KeyHash(name, key)

		case "witness":
			// witness <name> <vkey>
			// witness <name> <url> <vkey>
			if len(fields) < 3 || len(fields) > 4 {
				return nil, fmt.Errorf("witness: expected name [url] vkey")
			}
			policyName := fields[1]
			if policyName == "none" {
				return nil, fmt.Errorf("witness: %q is a reserved name", policyName)
			}
			if _, exists := p.groups[policyName]; exists {
				return nil, fmt.Errorf("witness: duplicate name %q", policyName)
			}
			var endpoint, vkeyStr string
			if len(fields) == 4 {
				endpoint = fields[2]
				vkeyStr = fields[3]
			} else {
				vkeyStr = fields[2]
			}
			signerName, keyType, key, err := note.ParseVKey(vkeyStr)
			if err != nil {
				return nil, fmt.Errorf("witness %s vkey: %w", policyName, err)
			}
			if keyType != note.Ed25519Cosigner {
				return nil, fmt.Errorf("witness %s vkey must use cosigner key type (0x%02x), got 0x%02x", policyName, note.Ed25519Cosigner, keyType)
			}
			w := &Witness{
				PolicyName: policyName,
				SignerName: signerName,
				Endpoint:   endpoint,
				Key:        key,
				keyHash:    note.CosignKeyHash(signerName, key),
			}
			p.witnesses[policyName] = w
			// Each witness gets an implicit singleton group so it can be
			// referenced directly in group and quorum directives.
			p.groups[policyName] = &Group{
				Threshold: 1,
				Members:   []*Group{{Witness: w}},
			}

		case "group":
			// group <name> <n|any|all> <member> [<member>...]
			if len(fields) < 4 {
				return nil, fmt.Errorf("group: expected name threshold member...")
			}
			policyName := fields[1]
			threshStr := fields[2]
			memberNames := fields[3:]
			if policyName == "none" {
				return nil, fmt.Errorf("group: %q is a reserved name", policyName)
			}
			if _, exists := p.groups[policyName]; exists {
				return nil, fmt.Errorf("group: duplicate name %q", policyName)
			}
			members := make([]*Group, 0, len(memberNames))
			for _, mn := range memberNames {
				g, exists := p.groups[mn]
				if !exists {
					return nil, fmt.Errorf("group %s: unknown member %q (must be defined before the group)", policyName, mn)
				}
				members = append(members, g)
			}
			var threshold int
			switch threshStr {
			case "any":
				threshold = 1
			case "all":
				threshold = len(members)
			default:
				n, err := strconv.Atoi(threshStr)
				if err != nil {
					return nil, fmt.Errorf("group %s: invalid threshold %q", policyName, threshStr)
				}
				if n < 0 || n > len(members) {
					return nil, fmt.Errorf("group %s: threshold %d out of range [0, %d]", policyName, n, len(members))
				}
				threshold = n
			}
			p.groups[policyName] = &Group{
				Threshold: threshold,
				Members:   members,
			}

		case "quorum":
			if len(fields) != 2 {
				return nil, fmt.Errorf("quorum: expected name or \"none\"")
			}
			p.quorumSet = true
			qname := fields[1]
			if qname == "none" {
				p.quorum = nil
			} else {
				g, exists := p.groups[qname]
				if !exists {
					return nil, fmt.Errorf("quorum: unknown name %q", qname)
				}
				p.quorum = g
			}

		default:
			return nil, fmt.Errorf("unknown directive: %q", fields[0])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if p.LogKey == nil {
		return nil, fmt.Errorf("policy missing log key")
	}
	if !p.quorumSet {
		return nil, fmt.Errorf("policy missing quorum")
	}
	return p, nil
}

// Verify checks that sigLines satisfies the policy: the log signature is valid
// and the quorum group is satisfied by the witness cosignatures.
//
// Each cosignature is matched by both signer name and the 4-byte key-hash
// prefix embedded in the raw signature bytes, providing defence-in-depth
// against key-confusion attacks where two signers share a name.
func (p *Policy) Verify(body string, sigLines []string) error {
	// Verify the log signature.
	logFound := false
	for _, line := range sigLines {
		name, err := note.SigName(line)
		if err != nil || name != p.LogName {
			continue
		}
		raw, err := note.DecodeSigLine(line)
		if err != nil {
			continue
		}
		if len(raw) < 4 || !bytes.Equal(raw[:4], p.logKeyHash[:]) {
			continue
		}
		if err := note.VerifySignature(body, line, p.LogKey); err != nil {
			return fmt.Errorf("log signature invalid: %w", err)
		}
		logFound = true
		break
	}
	if !logFound {
		return fmt.Errorf("log signature not found (expected signer %q)", p.LogName)
	}

	// "quorum none": no witnesses required.
	if p.quorum == nil {
		return nil
	}

	// Build the set of witnesses with valid cosignatures.
	witnessed := make(map[string]bool)
	for _, w := range p.witnesses {
		for _, line := range sigLines {
			name, err := note.SigName(line)
			if err != nil || name != w.SignerName {
				continue
			}
			raw, err := note.DecodeSigLine(line)
			if err != nil {
				continue
			}
			if len(raw) < 4 || !bytes.Equal(raw[:4], w.keyHash[:]) {
				continue
			}
			if err := note.VerifyCosignature(body, line, w.Key); err == nil {
				witnessed[w.SignerName] = true
			}
			break
		}
	}

	if !p.quorum.satisfied(witnessed) {
		return fmt.Errorf("insufficient cosignatures: quorum not satisfied")
	}
	return nil
}
