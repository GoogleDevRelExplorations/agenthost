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
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/spf13/viper"
	"google.golang.org/api/idtoken"
)

// AuthInterceptor is an A2A CallInterceptor that extracts and validates OIDC ID tokens.
// It attaches the validated user email and claims to the A2A call context.
type AuthInterceptor struct {
	// Store is the credential store used to construct DelegatedAuthProvider.
	Store auth.CredentialStore

	// Audience is the expected audience (client ID) for the OIDC ID token.
	// If empty, it will be read from "oauth.google.client_id" configuration.
	Audience string

	// Validator allows overriding the token validation logic (useful for unit tests).
	Validator func(ctx context.Context, token string, audience string) (*idtoken.Payload, error)
}

// NewAuthInterceptor creates a new AuthInterceptor.
func NewAuthInterceptor(store auth.CredentialStore) *AuthInterceptor {
	return &AuthInterceptor{Store: store}
}

// Before intercepts incoming A2A requests, extracts the Bearer token, validates it with Google's OIDC certs,
// and attaches the authenticated user email to both the Go context and A2A call context.
func (i *AuthInterceptor) Before(ctx context.Context, callCtx *a2asrv.CallContext, req *a2asrv.Request) (context.Context, any, error) {
	token := i.extractToken(callCtx)
	if token == "" {
		// No token provided. Proceed as anonymous / unauthenticated.
		return ctx, nil, nil
	}

	aud := i.Audience
	if aud == "" {
		aud = viper.GetString("oauth.google.client_id")
	}

	// Validate the ID token using OIDC validator
	validator := i.Validator
	if validator == nil {
		validator = idtoken.Validate
	}

	payload, err := validator(ctx, token, aud)
	if err != nil {
		return ctx, nil, fmt.Errorf("invalid OIDC credential: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return ctx, nil, fmt.Errorf("invalid OIDC payload: missing email claim")
	}

	// Attach authenticated user to A2A call context
	callCtx.User = a2asrv.NewAuthenticatedUser(email, payload.Claims)

	// Get DelegatedAuthProvider from Store and inject it into request context
	provider := i.Store.DelegatedProvider(ctx, email)
	ctx = auth.WithDelegatedAuthProvider(ctx, provider)

	return ctx, nil, nil
}

// After is a no-op after-execution hook required by the a2asrv.CallInterceptor interface.
func (i *AuthInterceptor) After(ctx context.Context, callCtx *a2asrv.CallContext, resp *a2asrv.Response) error {
	return nil
}

// extractToken pulls the Bearer token from the request metadata/headers.
func (i *AuthInterceptor) extractToken(callCtx *a2asrv.CallContext) string {
	if callCtx.ServiceParams() == nil {
		return ""
	}

	for _, key := range []string{"authorization", "Authorization"} {
		if vals, ok := callCtx.ServiceParams().Get(key); ok && len(vals) > 0 {
			authHeader := vals[0]
			if len(authHeader) > 7 && (authHeader[:7] == "Bearer " || authHeader[:7] == "bearer ") {
				return authHeader[7:]
			}
		}
	}

	return ""
}
