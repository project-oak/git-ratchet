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

package witness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// IssueScheme is the URL scheme naming a witness reached over GitHub Issues.
const IssueScheme = "github-issue"

// IssueTransport carries an add-checkpoint exchange to a github-issue witness:
// the request is an issue, the response is a comment on it.
//
// It is an http.RoundTripper, registered for the github-issue scheme, so a
// witness reached this way goes through the same client code as one reached
// over HTTP. Nothing above it knows which carrier it got.
//
// One issue carries one exchange. There is no reuse: a resubmission after a
// size conflict opens a new issue. Pairing two exchanges on one issue would
// rest on their ordering, and the witness is a workflow run per message, so
// two runs can finish out of order.
type IssueTransport struct {
	// API is the GitHub REST API root. Nil means https://api.github.com.
	API *url.URL
	// Token authenticates the issue and comment reads. It needs no more than
	// the ability to open an issue on the witness repository.
	Token string
	// Client talks to the GitHub API. Nil means http.DefaultClient. It must
	// not be a client this transport is registered on.
	Client *http.Client
	// Poll is how often to look for the witness's reply. Zero means 5s.
	Poll time.Duration
}

// httpFence matches the fenced block a message/http message travels in.
var httpFence = regexp.MustCompile("(?s)```http\n(.*?)```")

// RoundTrip submits the request as an issue and waits for the witness's reply.
//
// The deadline is the request context's: a witness is a workflow run, so a
// reply takes as long as that queues and runs.
func (t *IssueTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	owner, repo, err := issueTarget(req.URL)
	if err != nil {
		return nil, err
	}

	message, origin, err := issueRequest(req)
	if err != nil {
		return nil, err
	}

	ctx := req.Context()
	number, err := t.createIssue(ctx, owner, repo, "checkpoint: "+origin, fence(message))
	if err != nil {
		return nil, err
	}

	reply, err := t.awaitReply(ctx, owner, repo, number)
	if err != nil {
		return nil, fmt.Errorf("%s://%s/%s#%d: %w", IssueScheme, owner, repo, number, err)
	}
	// Parsing rather than assembling the response is what sets resp.Request,
	// which callers dereference, and what carries the Content-Type a size
	// conflict needs.
	return http.ReadResponse(bufio.NewReader(strings.NewReader(reply)), req)
}

// issueTarget splits a github-issue URL into the repository it names.
//
// The owner and repository say which issue thread to post to, so they are
// addressing rather than part of the resource being requested, and they do not
// travel in the message.
func issueTarget(u *url.URL) (owner, repo string, err error) {
	owner = u.Host
	repo = strings.Trim(u.Path, "/")
	if i := strings.IndexByte(repo, '/'); i >= 0 {
		repo = repo[:i]
	}
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("witness URL %q names no owner and repository", u)
	}
	return owner, repo, nil
}

// issueRequest renders the request as message/http, and reports the origin it
// is about. The origin titles the issue, which is what lets the witness
// serialise runs for one log against each other.
func issueRequest(req *http.Request) (message, origin string, err error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", "", fmt.Errorf("reading request body: %w", err)
	}
	origin, err = originFromAddCheckpoint(string(body))
	if err != nil {
		return "", "", err
	}

	out := req.Clone(req.Context())
	out.URL = &url.URL{Path: AddCheckpointPath}
	out.Host = MessageHost
	out.Body = io.NopCloser(bytes.NewReader(body))
	out.ContentLength = int64(len(body))
	// Left unset, Write inserts Go's default; the carrier is not a user agent.
	out.Header.Set("User-Agent", "")

	message, err = MarshalMessage(out)
	return message, origin, err
}

// originFromAddCheckpoint reads the log origin from an add-checkpoint body,
// which is the first line of the checkpoint after the proof.
func originFromAddCheckpoint(body string) (string, error) {
	_, note, found := strings.Cut(body, "\n\n")
	if !found {
		return "", fmt.Errorf("add-checkpoint body has no checkpoint")
	}
	origin, _, _ := strings.Cut(note, "\n")
	if origin == "" {
		return "", fmt.Errorf("checkpoint names no origin")
	}
	return origin, nil
}

func fence(message string) string {
	return "```http\n" + message + "```"
}

func (t *IssueTransport) awaitReply(ctx context.Context, owner, repo string, number int) (string, error) {
	interval := t.Poll
	if interval == 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		comments, closed, err := t.readIssue(ctx, owner, repo, number)
		if err != nil {
			return "", err
		}
		for _, c := range comments {
			if m := httpFence.FindStringSubmatch(c); m != nil {
				return m[1], nil
			}
		}
		// A witness that failed before answering says so in prose and closes
		// the issue. Waiting out the deadline for a reply that is not coming
		// would report a timeout instead of what went wrong.
		if closed {
			return "", fmt.Errorf("witness closed the issue without a response: %s",
				strings.TrimSpace(strings.Join(comments, "; ")))
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for a response: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (t *IssueTransport) api() *url.URL {
	if t.API != nil {
		return t.API
	}
	return DefaultAPIRoot()
}

// DefaultAPIRoot is the GitHub REST API root to use when none is configured.
//
// GitHub Actions sets GITHUB_API_URL, to api.github.com on github.com and to
// the instance's own API on Enterprise, so honouring it is what makes a witness
// on an Enterprise instance reachable.
func DefaultAPIRoot() *url.URL {
	if env := os.Getenv("GITHUB_API_URL"); env != "" {
		if u, err := url.Parse(env); err == nil && u.Host != "" {
			return u
		}
	}
	return &url.URL{Scheme: "https", Host: "api.github.com"}
}

func (t *IssueTransport) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, t.api().JoinPath(path).String(), rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(detail)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (t *IssueTransport) createIssue(ctx context.Context, owner, repo, title, body string) (int, error) {
	var created struct {
		Number int `json:"number"`
	}
	err := t.do(ctx, http.MethodPost, fmt.Sprintf("/repos/%s/%s/issues", owner, repo),
		map[string]string{"title": title, "body": body}, &created)
	if err != nil {
		return 0, fmt.Errorf("creating issue on %s/%s: %w", owner, repo, err)
	}
	return created.Number, nil
}

func (t *IssueTransport) readIssue(ctx context.Context, owner, repo string, number int) (comments []string, closed bool, err error) {
	var issue struct {
		State string `json:"state"`
	}
	if err := t.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/issues/%d", owner, repo, number), nil, &issue); err != nil {
		return nil, false, err
	}
	var got []struct {
		Body string `json:"body"`
	}
	if err := t.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/issues/%d/comments", owner, repo, number), nil, &got); err != nil {
		return nil, false, err
	}
	for _, c := range got {
		comments = append(comments, c.Body)
	}
	return comments, issue.State == "closed", nil
}
