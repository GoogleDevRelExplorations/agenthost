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

package auth

import (
	"context"
	"net/http"
)

// AuthRoundTripper injects an authentication header into outgoing requests.
type AuthRoundTripper struct {
	http.RoundTripper
	HeaderName  string
	HeaderValue string
}

// RoundTrip clones the request, injects the header, and delegates to the underlying transport.
func (rt *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set(rt.HeaderName, rt.HeaderValue)
	return rt.RoundTripper.RoundTrip(clone)
}

// NewAuthClient returns an *http.Client configured with an AuthRoundTripper.
func NewAuthClient(ctx context.Context, headerName, headerValue string) *http.Client {
	return &http.Client{
		Transport: &AuthRoundTripper{
			HeaderName:   headerName,
			HeaderValue:  headerValue,
			RoundTripper: http.DefaultTransport,
		},
	}
}
