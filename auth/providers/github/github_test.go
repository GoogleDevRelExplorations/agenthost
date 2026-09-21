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
	"testing"

	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	"golang.org/x/oauth2"
)

func TestGitHubAuth_Registration(t *testing.T) {
	prov, ok := providers.GetSigninProvider("github")
	if !ok {
		t.Fatalf("Expected github to be registered as SigninProvider")
	}
	if prov.Name() != "github" {
		t.Errorf("Expected name github, got %s", prov.Name())
	}
	scopes := prov.DefaultScopes()
	if len(scopes) == 0 {
		t.Errorf("Expected default scopes for github")
	}
}

func TestGitHubAuth_UserID(t *testing.T) {
	auth := &GitHubAuth{}

	// Test missing token
	if _, err := auth.UserID(context.Background(), nil); err == nil {
		t.Errorf("Expected error for nil token")
	}
	if _, err := auth.UserID(context.Background(), &oauth2.Token{}); err == nil {
		t.Errorf("Expected error for empty token")
	}
}
