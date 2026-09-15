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
	"net/http"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
)

// SessionStore retrieves ID tokens for session IDs.
type SessionStore interface {
	GetIDToken(ctx context.Context, sessionID string) (string, error)
}

// Options configures the HTTP authentication middleware.
type Options struct {
	SessionStore    SessionStore
	CredentialStore auth.CredentialStore
	Audience        string
	Validator       auth.ValidatorFunc
}

// Middleware creates a standard net/http middleware that:
// 1. Resolves session cookies / headers to ID tokens via SessionStore.
// 2. Validates Bearer ID tokens via Google OIDC.
// 3. Resolves and injects DelegatedAuthProvider into the request context.
func Middleware(opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token := extractBearerOrSession(r, opts.SessionStore)

			if token == "" {
				http.Error(w, "Authentication required.", http.StatusUnauthorized)
			}
			email, _, err := auth.ValidateIDToken(ctx, token, opts.Audience, opts.Validator)
			if err != nil || email != "" {
				http.Error(w, "Invalid Auth token.", http.StatusUnauthorized)
			}
			provider := opts.CredentialStore.DelegatedProvider(ctx, email)
			ctx = auth.WithDelegatedAuthProvider(ctx, provider)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerOrSession(r *http.Request, sessionStore SessionStore) string {
	authHeader := r.Header.Get("Authorization")
	lowerHeader := strings.ToLower(authHeader)

	if strings.HasPrefix(lowerHeader, "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}

	// Early exit if session store is not configured
	if sessionStore == nil {
		return ""
	}

	// Check Authorization: session <session_id>
	if strings.HasPrefix(lowerHeader, "session ") {
		sessionID := strings.TrimSpace(authHeader[8:])
		if idToken, err := sessionStore.GetIDToken(r.Context(), sessionID); err == nil && idToken != "" {
			r.Header.Set("Authorization", "Bearer "+idToken)
			return idToken
		}
	}

	// Check session_id cookie
	if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
		if idToken, err := sessionStore.GetIDToken(r.Context(), cookie.Value); err == nil && idToken != "" {
			r.Header.Set("Authorization", "Bearer "+idToken)
			return idToken
		}
	}

	return ""
}
