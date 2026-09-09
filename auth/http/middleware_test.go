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
	"google.golang.org/api/idtoken"
)

type mockSessionStore map[string]string

func (m mockSessionStore) GetIDToken(ctx context.Context, sessionID string) (string, error) {
	if tok, ok := m[sessionID]; ok {
		return tok, nil
	}
	return "", fmt.Errorf("session not found")
}

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
		if provider.Email() != "user@example.com" {
			t.Errorf("Expected email user@example.com, got %s", provider.Email())
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

func TestHTTPMiddleware_SessionHeader(t *testing.T) {
	sessionStore := mockSessionStore{
		"sess-123": "valid-token",
	}
	credStore := auth.NewInMemoryStore()

	handler := Middleware(Options{
		SessionStore:    sessionStore,
		CredentialStore: credStore,
		Audience:        "test-aud",
		Validator:       mockValidator,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-token" {
			t.Errorf("Expected Authorization header to be rewritten to Bearer valid-token, got %s", authHeader)
		}
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context")
			return
		}
		if provider.Email() != "user@example.com" {
			t.Errorf("Expected email user@example.com, got %s", provider.Email())
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
	sessionStore := mockSessionStore{
		"cookie-sess-456": "valid-token",
	}
	credStore := auth.NewInMemoryStore()

	handler := Middleware(Options{
		SessionStore:    sessionStore,
		CredentialStore: credStore,
		Audience:        "test-aud",
		Validator:       mockValidator,
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer valid-token" {
			t.Errorf("Expected Authorization header to be rewritten to Bearer valid-token, got %s", authHeader)
		}
		provider, ok := auth.DelegatedAuthProviderFrom(r.Context())
		if !ok || provider == nil {
			t.Errorf("Expected DelegatedAuthProvider in context")
			return
		}
		if provider.Email() != "user@example.com" {
			t.Errorf("Expected email user@example.com, got %s", provider.Email())
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
