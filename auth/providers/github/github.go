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

package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func init() {
	registry.RegisterProvider(registry.Provider{
		Name:     "github",
		Type:     registry.AuthTypeOAuth2,
		Endpoint: github.Endpoint,
		Scopes: []registry.Scope{
			{
				Value:       "read:user",
				Name:        "Read User Profile",
				Description: "Access profile information (username, avatar, bio).",
				Default:     true,
			},
			{
				Value:       "user:email",
				Name:        "User Email Addresses",
				Description: "Read your email addresses dynamically.",
				Default:     true,
			},
			{
				Value:       "repo",
				Name:        "Repository Access",
				Description: "Full control over public and private repositories, including comments, actions, and commits.",
				Default:     true,
			},
			{
				Value:       "public_repo",
				Name:        "Public Repository Access (Read-only)",
				Description: "Access to read content/commits of public repositories.",
				Default:     false,
			},
			{
				Value:       "gist",
				Name:        "Gist Management",
				Description: "Read, write, and manage your GitHub Gists.",
				Default:     false,
			},
		},
		HTTPClient: func(ctx context.Context, cred []byte) (*http.Client, error) {
			var tok oauth2.Token
			if err := json.Unmarshal(cred, &tok); err != nil {
				return nil, fmt.Errorf("failed to unmarshal oauth2 token: %w", err)
			}
			return auth.NewAuthClient(ctx, "Authorization", "Bearer "+tok.AccessToken), nil
		},
	})
}
