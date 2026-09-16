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
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
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
	})

	providers.RegisterSigninProvider(&GitHubAuth{})
}

// GitHubAuth implements providers.SigninProvider for GitHub OAuth2 authentication.
type GitHubAuth struct{}

func (g *GitHubAuth) Name() string {
	return "github"
}

func (g *GitHubAuth) Endpoint() oauth2.Endpoint {
	return github.Endpoint
}

func (g *GitHubAuth) DefaultScopes() []string {
	return []string{"read:user", "user:email"}
}

// UserID resolves the user's GitHub login handle using the OAuth access token.
func (g *GitHubAuth) UserID(ctx context.Context, tok *oauth2.Token) (string, error) {
	if tok == nil || tok.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("User-Agent", "agenthost")
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch github user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github user endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to decode github user: %w", err)
	}
	if user.Login == "" {
		return "", errors.New("github user login is empty")
	}
	return user.Login, nil
}
