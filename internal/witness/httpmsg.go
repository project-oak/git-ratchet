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
	"bytes"
	"fmt"
	"io"
	"strings"
)

// An add-checkpoint exchange that cannot use a socket -- a github-issue
// witness, where the request is an issue and the response a comment -- carries
// the same HTTP messages the tlog-witness protocol defines, serialised as
// message/http (RFC 9112). Nothing about the protocol changes; only the wire.
//
// Both directions are the standard library's: http.Request.Write and
// http.ReadRequest, http.Response.Write and http.ReadResponse. What this file
// adds is the line-ending rule below.

// AddCheckpointPath is the request target an add-checkpoint message carries.
// The owner and repository addressing a github-issue witness say which thread
// to post to, not which resource is being addressed, so they do not appear in
// the message: a witness routes it exactly as it would an HTTP request.
const AddCheckpointPath = "/add-checkpoint"

// MessageHost is the Host an add-checkpoint request message carries.
//
// RFC 9112 requires a Host on every HTTP/1.1 request, but one message may be
// carried to several witnesses and the carrier addresses them out of band, so
// there is no host to name. A reserved name (RFC 2606) says that rather than
// implying an address that could be resolved.
const MessageHost = "witness.invalid"

// MarshalMessage serialises an HTTP request or response, with LF line endings
// in place of the CRLF that RFC 9112 specifies.
//
// GitHub normalises CRLF to LF in issue and comment text, so a message sent
// with CRLF does not come back as it was sent. Sending LF makes the two
// identical, and Go's parsers accept it. Nothing may depend on the
// serialisation being stable in any case: it is a wire, not something signed.
//
// The body must not contain a carriage return, since the rewrite cannot tell
// one in the framing from one in the body. Bodies here are signed notes and
// base64 proof lines, which are LF-terminated by construction.
func MarshalMessage(m interface{ Write(io.Writer) error }) (string, error) {
	var buf bytes.Buffer
	if err := m.Write(&buf); err != nil {
		return "", fmt.Errorf("serialising message: %w", err)
	}
	out := strings.ReplaceAll(buf.String(), "\r\n", "\n")
	if strings.ContainsRune(out, '\r') {
		return "", fmt.Errorf("message contains a carriage return outside its line endings")
	}
	return out, nil
}
