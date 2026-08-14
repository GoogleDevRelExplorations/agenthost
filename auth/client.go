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
	"fmt"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
)

// AuthRoundTripper injects an authentication header into outgoing requests.
type AuthRoundTripper struct {
	http.RoundTripper
	AuthProvider string
}

// RoundTrip clones the request, injects the header, and delegates to the underlying transport.
func (rt *AuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	provider, ok := DelegatedAuthProviderFrom(req.Context())
	if !ok || provider == nil {
		return nil, fmt.Errorf("authentication error: delegated auth provider not found in context")
	}
	if rt.AuthProvider == "" {
		return nil, fmt.Errorf("auth provider must be specified")
	}
	tok, err := provider.GetCredential(req.Context(), rt.AuthProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %v", err)
	}
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+string(tok))
	return rt.RoundTripper.RoundTrip(clone)
}

// NewClient returns an *http.Client configured with an AuthRoundTripper.
func NewClient(provider string) (*http.Client, error) {
	_, ok := registry.GetProvider(provider)
	if !ok {
		return nil, fmt.Errorf("unknown auth provider: %s", provider)
	}
	return &http.Client{
		Transport: &AuthRoundTripper{
			AuthProvider: provider,
			RoundTripper: http.DefaultTransport,
		},
	}, nil
}
