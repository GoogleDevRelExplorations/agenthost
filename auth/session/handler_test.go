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

package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	"github.com/spf13/viper"
)

func TestHandler_HandleStatus_RedirectWhenNoSession(t *testing.T) {
	store := NewInMemoryStore()
	credStore := auth.NewInMemoryStore()
	h := NewHandler(store, credStore, "http://localhost:9001", "github", nil)

	req := httptest.NewRequest("GET", "/status", nil)
	rec := httptest.NewRecorder()

	h.HandleStatus(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303 SeeOther, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Expected redirect to /login, got %q", loc)
	}
}

func TestHandler_HandleStatus_Authenticated(t *testing.T) {
	store := NewInMemoryStore()
	credStore := auth.NewInMemoryStore()
	h := NewHandler(store, credStore, "http://localhost:9001", "github", nil)

	ctx := context.Background()
	sessionID := "sess-xyz"
	err := store.SetSession(ctx, &SessionData{
		ID:        sessionID,
		UserID:    "octocat",
		Provider:  "github",
		CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	req := httptest.NewRequest("GET", "/status", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: sessionID,
	})
	rec := httptest.NewRecorder()

	h.HandleStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHandler_HandleLogin_RedirectToOAuth(t *testing.T) {
	store := NewInMemoryStore()
	credStore := auth.NewInMemoryStore()

	viper.Set("oauth.github.client_id", "test-client-id")
	viper.Set("oauth.github.client_secret", "test-client-secret")

	h := NewHandler(store, credStore, "http://localhost:9001", "github", nil)

	req := httptest.NewRequest("GET", "/login", nil)
	rec := httptest.NewRecorder()

	h.HandleLogin(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("Expected status 303, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("Expected redirect Location header")
	}
	if !strings.Contains(loc, "github.com/login/oauth/authorize") {
		t.Errorf("Expected redirect to github oauth authorize, got %q", loc)
	}
}
