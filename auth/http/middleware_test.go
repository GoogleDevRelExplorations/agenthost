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

package http

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func mockValidator(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	if token == "valid-token" {
		return &idtoken.Payload{
			Claims: map[string]any{
				"email": "user@example.com",
			},
		}, nil
	}
	return nil, fmt.Errorf("invalid token: %s", token)
}

func TestHTTPMiddleware_BearerToken(t *testing.T) {
	credStore := auth.NewInMemoryStore()
	handler := Middleware(Options{
		CredentialStore: credStore,
		Audience:        "test-aud",
		Validator:       mockValidator,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context, got none")
			return
		}
		if provider.UserID() != "user@example.com" {
			t.Errorf("Expected UserID user@example.com, got %s", provider.UserID())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_BearerSessionID(t *testing.T) {
	sessionStore := authsession.NewInMemoryStore()
	_ = sessionStore.SetSession(context.Background(), &auth.SessionData{
		ID:     "sess-123",
		UserID: "octocat",
	})
	credStore := auth.NewInMemoryStore()

	handler := Middleware(Options{
		SessionStore:    sessionStore,
		CredentialStore: credStore,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context")
			return
		}
		if provider.UserID() != "octocat" {
			t.Errorf("Expected UserID octocat, got %s", provider.UserID())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer sess-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_SessionSchemeSupported(t *testing.T) {
	sessionStore := authsession.NewInMemoryStore()
	_ = sessionStore.SetSession(context.Background(), &auth.SessionData{
		ID:     "sess-123",
		UserID: "octocat",
	})
	credStore := auth.NewInMemoryStore()

	handler := Middleware(Options{
		SessionStore:    sessionStore,
		CredentialStore: credStore,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected 'session' scheme to be supported")
			return
		}
		if provider.UserID() != "octocat" {
			t.Errorf("Expected UserID octocat, got %s", provider.UserID())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "session sess-123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_SessionCookie(t *testing.T) {
	sessionStore := authsession.NewInMemoryStore()
	_ = sessionStore.SetSession(context.Background(), &auth.SessionData{
		ID:     "cookie-sess-456",
		UserID: "user@example.com",
	})
	credStore := auth.NewInMemoryStore()

	handler := Middleware(Options{
		SessionStore:    sessionStore,
		CredentialStore: credStore,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context")
			return
		}
		if provider.UserID() != "user@example.com" {
			t.Errorf("Expected UserID user@example.com, got %s", provider.UserID())
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: "cookie-sess-456",
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestHTTPMiddleware_Unauthenticated(t *testing.T) {
	handler := Middleware(Options{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if ok || provider != nil {
			t.Errorf("Expected no DelegatedAuthProvider in context for anonymous request")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

type mockSigninProvider struct {
	name   string
	userID string
}

func (m *mockSigninProvider) Name() string                  { return m.name }
func (m *mockSigninProvider) Endpoint() oauth2.Endpoint    { return oauth2.Endpoint{} }
func (m *mockSigninProvider) DefaultScopes() []string       { return nil }
func (m *mockSigninProvider) UserID(ctx context.Context, tok *oauth2.Token) (string, error) {
	if tok != nil && tok.AccessToken == "valid-oauth-token" {
		return m.userID, nil
	}
	return "", fmt.Errorf("invalid oauth token")
}

func TestHTTPMiddleware_OAuthAccessToken(t *testing.T) {
	providers.RegisterSigninProvider(&mockSigninProvider{name: "mock-oauth", userID: "custom-user"})

	credStore := auth.NewInMemoryStore()
	handler := Middleware(Options{
		CredentialStore: credStore,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context")
			return
		}
		if provider.UserID() != "custom-user" {
			t.Errorf("Expected UserID custom-user, got %s", provider.UserID())
		}
		// Verify token was stored in credential store
		cred, err := provider.GetCredential(r.Context(), "mock-oauth")
		if err != nil || len(cred) == 0 {
			t.Errorf("Expected credential for mock-oauth, got err: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-oauth-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}
