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

package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"golang.org/x/oauth2"
)

// AuthInterceptor is an A2A CallInterceptor that extracts and validates auth tokens,
// accepting both 'session' and 'bearer' schemes (session ID or OAuth access token).
type AuthInterceptor struct {
	Store        auth.CredentialStore
	SessionStore auth.SessionStore
	Audience     string
	Validator    auth.ValidatorFunc
}

// NewAuthInterceptor creates a new A2A CallInterceptor.
func NewAuthInterceptor(store auth.CredentialStore, sessionStore auth.SessionStore) *AuthInterceptor {
	return &AuthInterceptor{
		Store:        store,
		SessionStore: sessionStore,
	}
}

// Before intercepts incoming A2A requests, validates the token (supporting 'session' and 'bearer'),
// sets the A2A User, and injects the DelegatedAuthProvider into the Go context.
func (i *AuthInterceptor) Before(ctx context.Context, callCtx *a2asrv.CallContext, req *a2asrv.Request) (context.Context, any, error) {
	scheme, token := i.extractToken(callCtx)
	if token == "" {
		// If no token was provided in A2A params, check if context was already authenticated by HTTP middleware
		if provider, ok := auth.DelegatedAuthProviderFrom(ctx); ok && provider != nil && provider.UserID() != "" {
			callCtx.User = a2asrv.NewAuthenticatedUser(provider.UserID(), map[string]any{"user_id": provider.UserID()})
		}
		return ctx, nil, nil
	}

	var userID string
	var claims map[string]any

	if scheme == "session" {
		if i.SessionStore != nil {
			if uid, err := i.SessionStore.GetUserID(ctx, token); err == nil && uid != "" {
				userID = uid
				claims = map[string]any{"user_id": userID}
			}
		}
	} else if scheme == "bearer" {
		// 1) Type 1: Session ID
		if i.SessionStore != nil {
			if uid, err := i.SessionStore.GetUserID(ctx, token); err == nil && uid != "" {
				userID = uid
				claims = map[string]any{"user_id": userID}
			}
		}

		// 2) Type 2: OAuth access token
		if userID == "" {
			if i.Validator != nil {
				email, c, err := auth.ValidateIDToken(ctx, token, i.Audience, i.Validator)
				if err == nil && email != "" {
					userID = email
					claims = c
					if i.Store != nil {
						tokBytes, _ := json.Marshal(&oauth2.Token{
							AccessToken: token,
							TokenType:   "Bearer",
						})
						_ = i.Store.SetCredential(ctx, userID, "google", tokBytes)
					}
				}
			}
			if userID == "" {
				tok := &oauth2.Token{AccessToken: token, TokenType: "Bearer"}
				for _, p := range providers.ListSigninProviders() {
					if uid, err := p.UserID(ctx, tok); err == nil && uid != "" {
						userID = uid
						claims = map[string]any{"user_id": uid, "provider": p.Name()}
						if i.Store != nil {
							tokBytes, _ := json.Marshal(tok)
							_ = i.Store.SetCredential(ctx, userID, p.Name(), tokBytes)
						}
						break
					}
				}
			}
		}
	} else {
		// Bare token without scheme
		if i.SessionStore != nil {
			if uid, err := i.SessionStore.GetUserID(ctx, token); err == nil && uid != "" {
				userID = uid
				claims = map[string]any{"user_id": userID}
			}
		}
		if userID == "" {
			tok := &oauth2.Token{AccessToken: token, TokenType: "Bearer"}
			for _, p := range providers.ListSigninProviders() {
				if uid, err := p.UserID(ctx, tok); err == nil && uid != "" {
					userID = uid
					claims = map[string]any{"user_id": uid, "provider": p.Name()}
					if i.Store != nil {
						tokBytes, _ := json.Marshal(tok)
						_ = i.Store.SetCredential(ctx, userID, p.Name(), tokBytes)
					}
					break
				}
			}
		}
	}

	// Fallback to existing context authentication if token resolution didn't succeed directly
	if userID == "" {
		if provider, ok := auth.DelegatedAuthProviderFrom(ctx); ok && provider != nil && provider.UserID() != "" {
			userID = provider.UserID()
			claims = map[string]any{"user_id": userID}
		}
	}

	if userID == "" {
		return ctx, nil, fmt.Errorf("invalid auth token: authentication failed")
	}

	// Populates the authenticated user identity on the A2A call context
	callCtx.User = a2asrv.NewAuthenticatedUser(userID, claims)

	if i.Store != nil {
		provider := i.Store.DelegatedProvider(ctx, userID)
		ctx = auth.WithDelegatedAuthProvider(ctx, provider)
	}

	return ctx, nil, nil
}

// After is a no-op post-execution hook required by the a2asrv.CallInterceptor interface.
func (i *AuthInterceptor) After(ctx context.Context, callCtx *a2asrv.CallContext, resp *a2asrv.Response) error {
	return nil
}

func (i *AuthInterceptor) extractToken(callCtx *a2asrv.CallContext) (string, string) {
	if callCtx.ServiceParams() == nil {
		return "", ""
	}

	// ServiceParams().Get is case-insensitive
	if vals, ok := callCtx.ServiceParams().Get("authorization"); ok && len(vals) > 0 {
		authHeader := strings.TrimSpace(vals[0])
		lower := strings.ToLower(authHeader)
		if strings.HasPrefix(lower, "bearer ") {
			return "bearer", strings.TrimSpace(authHeader[7:])
		}
		if strings.HasPrefix(lower, "session ") {
			return "session", strings.TrimSpace(authHeader[8:])
		}
		return "", authHeader
	}
	return "", ""
}
