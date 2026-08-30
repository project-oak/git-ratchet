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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
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
	for {
		comments, closed, err := t.readIssue(ctx, owner, repo, number)
		if err != nil {
			pause, limited := rateLimitPause(err)
			if !limited {
				return "", err
			}
			if err := sleep(ctx, min(pause, interval*12)); err != nil {
				return "", err
			}
			continue
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
		if err := sleep(ctx, interval); err != nil {
			return "", err
		}
	}
}

// sleep waits, or returns why it could not.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Second
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting for a response: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// apiRoot is the GitHub REST API root, which go-github requires to end in a
// slash.
func (t *IssueTransport) apiRoot() *url.URL {
	u := t.API
	if u == nil {
		u = DefaultAPIRoot()
	}
	if !strings.HasSuffix(u.Path, "/") {
		withSlash := *u
		withSlash.Path += "/"
		return &withSlash
	}
	return u
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

// github returns a client for the API root this transport is configured with.
//
// Its HTTP client must not be one this transport is registered on, or a
// request to a witness would recurse into itself.
func (t *IssueTransport) github() *github.Client {
	c := github.NewClient(t.Client).WithAuthToken(t.Token)
	c.BaseURL = t.apiRoot()
	return c
}

func (t *IssueTransport) createIssue(ctx context.Context, owner, repo, title, body string) (int, error) {
	issue, _, err := t.github().Issues.Create(ctx, owner, repo,
		&github.IssueRequest{Title: &title, Body: &body})
	if err != nil {
		return 0, fmt.Errorf("creating issue on %s/%s: %w", owner, repo, err)
	}
	return issue.GetNumber(), nil
}

func (t *IssueTransport) readIssue(ctx context.Context, owner, repo string, number int) (comments []string, closed bool, err error) {
	c := t.github()
	issue, _, err := c.Issues.Get(ctx, owner, repo, number)
	if err != nil {
		return nil, false, err
	}

	opts := &github.IssueListCommentsOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		page, resp, err := c.Issues.ListComments(ctx, owner, repo, number, opts)
		if err != nil {
			return nil, false, err
		}
		for _, comment := range page {
			comments = append(comments, comment.GetBody())
		}
		if resp.NextPage == 0 {
			return comments, issue.GetState() == "closed", nil
		}
		opts.Page = resp.NextPage
	}
}

// rateLimitPause reports how long to wait before retrying, and whether the
// error was a rate limit at all.
//
// Polling for a reply is a request every few seconds for as long as the
// witness's workflow takes, so hitting a limit is a matter of waiting rather
// than a failure. Anything else is reported.
func rateLimitPause(err error) (time.Duration, bool) {
	var rl *github.RateLimitError
	if errors.As(err, &rl) {
		return time.Until(rl.Rate.Reset.Time), true
	}
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &abuse) {
		if abuse.RetryAfter != nil {
			return *abuse.RetryAfter, true
		}
		return time.Minute, true
	}
	return 0, false
}
