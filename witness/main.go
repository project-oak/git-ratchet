// Package main implements a C2SP-aligned Git Checkpoint Witness HTTP server.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/BenBirt/git-ratchet/internal/gitutil"
	"github.com/BenBirt/git-ratchet/internal/note"
)

type Server struct {
	witnessKey     *note.Signer
	trustedOrigins map[string]ed25519.PublicKey
	stateFile      string
	mu             sync.RWMutex
	commits        map[string]string // branch key -> commit hash
}

var (
	addr        = flag.String("addr", ":8080", "Address to listen on")
	keyPath     = flag.String("key", "", "Path to witness private key file (required)")
	originsFlag = flag.String("origins", "", "Comma-separated list of trusted origin verifier keys (vkeys)")
	originsFile = flag.String("origins-file", "", "Path to file containing trusted origin verifier keys (one per line)")
	stateFile   = flag.String("state-file", "", "Path to JSON file to persist witness state")
)

func main() {
	flag.Parse()

	if *keyPath == "" {
		log.Fatalf("error: --key is required")
	}

	// Read witness signer key.
	wSigner, err := note.ReadKeyFile(*keyPath)
	if err != nil {
		log.Fatalf("failed to read witness key: %v", err)
	}

	// Accumulate trusted origins.
	var rawOrigins []string
	if *originsFlag != "" {
		rawOrigins = append(rawOrigins, strings.Split(*originsFlag, ",")...)
	}
	if *originsFile != "" {
		fileOrigins, err := readOriginsFile(*originsFile)
		if err != nil {
			log.Fatalf("failed to read origins file: %v", err)
		}
		rawOrigins = append(rawOrigins, fileOrigins...)
	}

	trustedOrigins, err := parseOrigins(rawOrigins)
	if err != nil {
		log.Fatalf("failed to parse trusted origins: %v", err)
	}

	srv := &Server{
		witnessKey:     wSigner,
		trustedOrigins: trustedOrigins,
		stateFile:      *stateFile,
		commits:        make(map[string]string),
	}

	// Load stored state if any.
	if err := srv.loadState(); err != nil {
		log.Fatalf("failed to load state file: %v", err)
	}

	http.HandleFunc("/add-checkpoint", srv.handleAddCheckpoint)

	log.Printf("Starting witness %q on %s", wSigner.Name, *addr)
	if len(srv.trustedOrigins) > 0 {
		log.Printf("Trusted origins: %d configured", len(srv.trustedOrigins))
	} else {
		log.Printf("WARNING: no trusted origins configured. All submissions will fail with 404!")
	}

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func (s *Server) handleAddCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading request body failed", http.StatusBadRequest)
		return
	}
	bodyStr := string(bodyBytes)

	// Split body into ancestry proof and signed note.
	lines := strings.Split(bodyStr, "\n")
	var ancestry []string
	var signedNote string
	emptyLineIdx := -1
	for i, line := range lines {
		if line == "" {
			emptyLineIdx = i
			break
		}
		ancestry = append(ancestry, line)
	}
	if emptyLineIdx < 0 {
		http.Error(w, "malformed request: missing empty line separator", http.StatusBadRequest)
		return
	}
	signedNote = strings.Join(lines[emptyLineIdx+1:], "\n")

	// Parse checkpoint signed note.
	noteBody, sigLines, err := note.ParseSignedNote(signedNote)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse signed note: %v", err), http.StatusBadRequest)
		return
	}
	if len(sigLines) == 0 {
		http.Error(w, "missing origin signature", http.StatusBadRequest)
		return
	}

	// Extract origin signer name and lookup key.
	originSigName, err := note.SigName(sigLines[0])
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse origin signer name: %v", err), http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	originPub, ok := s.trustedOrigins[originSigName]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, fmt.Sprintf("unauthorized origin: %s", originSigName), http.StatusNotFound)
		return
	}

	// Verify origin signature.
	if err := note.VerifySignature(noteBody, sigLines[0], originPub); err != nil {
		http.Error(w, fmt.Sprintf("invalid origin signature: %v", err), http.StatusForbidden)
		return
	}

	// Parse checkpoint body: "<origin> <ref>\n<commit-hash>\n"
	bodyLines := strings.Split(strings.TrimSpace(noteBody), "\n")
	if len(bodyLines) < 2 {
		http.Error(w, "malformed checkpoint body", http.StatusBadRequest)
		return
	}
	refParts := strings.Fields(bodyLines[0])
	if len(refParts) != 2 {
		http.Error(w, "malformed ref line in checkpoint body", http.StatusBadRequest)
		return
	}
	ref := refParts[1]
	stateKey := refParts[0] + " " + ref
	newCommit := strings.TrimSpace(bodyLines[1])

	s.mu.Lock()
	defer s.mu.Unlock()

	storedCommit := s.commits[stateKey]

	if storedCommit != "" && newCommit != storedCommit {
		refKind, err := gitutil.ParseRefKind(ref)
		if err != nil {
			http.Error(w, fmt.Sprintf("unrecognised ref: %v", err), http.StatusBadRequest)
			return
		}
		if refKind == gitutil.RefTag {
			// Tag pinning: refuse any change to the stored commit.
			http.Error(w, fmt.Sprintf(
				"tag checkpoint rejected: stored commit %s differs from submitted commit %s; tags are immutable",
				storedCommit, newCommit), http.StatusConflict)
			return
		}

		// Branch ratchet: ancestry verification required.
		commitMap := make(map[string]string)
		for _, b64Obj := range ancestry {
			decoded, err := base64.StdEncoding.DecodeString(b64Obj)
			if err != nil {
				http.Error(w, "malformed base64 encoding in ancestry proof", http.StatusUnprocessableEntity)
				return
			}
			commitID, err := gitutil.CommitHash(decoded, len(newCommit))
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid commit object in ancestry proof: %v", err), http.StatusUnprocessableEntity)
				return
			}
			s := string(decoded)
			idx := strings.IndexByte(s, '\n')
			if idx >= 0 {
				commitMap[commitID] = s[idx+1:]
			}
		}

		// Traverse ancestry DAG backward from newCommit to storedCommit.
		queue := []string{newCommit}
		visited := map[string]bool{newCommit: true}
		found := false

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			if curr == storedCommit {
				found = true
				break
			}

			content, ok := commitMap[curr]
			if !ok {
				// Parent commit content not in the ancestry proof.
				continue
			}

			parents := parseParents(content)
			for _, p := range parents {
				if !visited[p] {
					visited[p] = true
					queue = append(queue, p)
				}
			}
		}

		if !found {
			http.Error(w, "ancestry verification failed: new commit does not descend from stored commit", http.StatusUnprocessableEntity)
			return
		}
	}

	// Update stored state if it's empty, or if verification succeeded and newCommit != storedCommit.
	if storedCommit != newCommit {
		s.commits[stateKey] = newCommit
		if err := s.saveState(); err != nil {
			log.Printf("error saving state file: %v", err)
			http.Error(w, "internal server error: saving state failed", http.StatusInternalServerError)
			return
		}
	}

	// Cosign checkpoint.
	cosigLine, err := note.Cosign(signedNote, s.witnessKey)
	if err != nil {
		log.Printf("error generating cosignature: %v", err)
		http.Error(w, "internal server error: signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, cosigLine)
}

func parseParents(content string) []string {
	var parents []string
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "parent ") {
			parents = append(parents, strings.TrimPrefix(line, "parent "))
		}
	}
	return parents
}

func (s *Server) loadState() error {
	if s.stateFile == "" {
		return nil
	}
	data, err := os.ReadFile(s.stateFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.commits)
}

func (s *Server) saveState() error {
	if s.stateFile == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.commits, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.stateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.stateFile)
}

func readOriginsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var vkeys []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		vkeys = append(vkeys, line)
	}
	return vkeys, scanner.Err()
}

func parseOrigins(origins []string) (map[string]ed25519.PublicKey, error) {
	res := make(map[string]ed25519.PublicKey)
	for _, vkey := range origins {
		vkey = strings.TrimSpace(vkey)
		if vkey == "" {
			continue
		}
		name, pub, err := note.ParseVKey(vkey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse trusted origin vkey %q: %w", vkey, err)
		}
		res[name] = pub
	}
	return res, nil
}
