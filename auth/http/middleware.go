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
	"encoding/json"
	"net/http"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	"golang.org/x/oauth2"
)

// Options configures the HTTP authentication middleware.
type Options struct {
	SessionStore    auth.SessionStore
	CredentialStore auth.CredentialStore
	Audience        string
	Validator       auth.ValidatorFunc
}

// Middleware creates a standard net/http middleware that:
// 1. Accepts Authorization headers with both:
//    - "Bearer <token>" (supporting either a session ID or an OAuth access token)
//    - "Session <session_id>" (for legacy tools and MCP clients)
// 2. Falls back to session cookie if no Authorization header is provided.
// 3. Resolves and injects DelegatedAuthProvider into the request context.
func Middleware(opts Options) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var userID string

			authHeader := r.Header.Get("Authorization")
			lowerHeader := strings.ToLower(authHeader)

			if strings.HasPrefix(lowerHeader, "session ") {
				// Legacy "session <session_id>" header
				sessionID := strings.TrimSpace(authHeader[8:])
				if opts.SessionStore != nil && sessionID != "" {
					if uid, err := opts.SessionStore.GetUserID(ctx, sessionID); err == nil && uid != "" {
						userID = uid
					}
				}
			} else if strings.HasPrefix(lowerHeader, "bearer ") {
				bearerToken := strings.TrimSpace(authHeader[7:])
				if bearerToken != "" {
					// 1) Type 1: Session ID
					if opts.SessionStore != nil {
						if uid, err := opts.SessionStore.GetUserID(ctx, bearerToken); err == nil && uid != "" {
							userID = uid
						}
					}

					// 2) Type 2: OAuth access token
					if userID == "" {
						if opts.Validator != nil {
							email, _, err := auth.ValidateIDToken(ctx, bearerToken, opts.Audience, opts.Validator)
							if err == nil && email != "" {
								userID = email
								if opts.CredentialStore != nil {
									tokBytes, _ := json.Marshal(&oauth2.Token{
										AccessToken: bearerToken,
										TokenType:   "Bearer",
									})
									_ = opts.CredentialStore.SetCredential(ctx, userID, "google", tokBytes)
								}
							}
						}
						if userID == "" {
							tok := &oauth2.Token{AccessToken: bearerToken, TokenType: "Bearer"}
							for _, p := range providers.ListSigninProviders() {
								if uid, err := p.UserID(ctx, tok); err == nil && uid != "" {
									userID = uid
									if opts.CredentialStore != nil {
										tokBytes, _ := json.Marshal(tok)
										_ = opts.CredentialStore.SetCredential(ctx, userID, p.Name(), tokBytes)
									}
									break
								}
							}
						}
					}
				}
			}

			// 2. Fall back to session cookie (for browser navigation)
			if userID == "" && opts.SessionStore != nil {
				if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
					if uid, err := opts.SessionStore.GetUserID(ctx, cookie.Value); err == nil && uid != "" {
						userID = uid
					}
				}
			}

			// 3. If authenticated, inject DelegatedAuthProvider for userID
			if userID != "" && opts.CredentialStore != nil {
				provider := opts.CredentialStore.DelegatedProvider(ctx, userID)
				ctx = auth.WithDelegatedAuthProvider(ctx, provider)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
