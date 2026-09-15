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
	"fmt"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// AuthInterceptor is an A2A CallInterceptor that extracts and validates OIDC ID tokens.
type AuthInterceptor struct {
	Store     auth.CredentialStore
	Audience  string
	Validator auth.ValidatorFunc
}

// NewAuthInterceptor creates a new A2A CallInterceptor.
func NewAuthInterceptor(store auth.CredentialStore) *AuthInterceptor {
	return &AuthInterceptor{Store: store}
}

// Before intercepts incoming A2A requests, validates the ID token, sets the A2A User,
// and injects the DelegatedAuthProvider into the Go context.
func (i *AuthInterceptor) Before(ctx context.Context, callCtx *a2asrv.CallContext, req *a2asrv.Request) (context.Context, any, error) {
	token := i.extractToken(callCtx)
	if token == "" {
		return ctx, nil, fmt.Errorf("Unauthenticated %w", a2a.ErrUnauthenticated)
	}

	email, claims, err := auth.ValidateIDToken(ctx, token, i.Audience, i.Validator)
	if err != nil {
		return ctx, nil, err
	}

	// Populates the authenticated user identity on the A2A call context
	callCtx.User = a2asrv.NewAuthenticatedUser(email, claims)

	if i.Store != nil {
		provider := i.Store.DelegatedProvider(ctx, email)
		ctx = auth.WithDelegatedAuthProvider(ctx, provider)
	}

	return ctx, nil, nil
}

// After is a no-op post-execution hook required by the a2asrv.CallInterceptor interface.
func (i *AuthInterceptor) After(ctx context.Context, callCtx *a2asrv.CallContext, resp *a2asrv.Response) error {
	return nil
}

func (i *AuthInterceptor) extractToken(callCtx *a2asrv.CallContext) string {
	if callCtx.ServiceParams() == nil {
		return ""
	}

	// ServiceParams().Get is case-insensitive
	if vals, ok := callCtx.ServiceParams().Get("authorization"); ok && len(vals) > 0 {
		authHeader := vals[0]
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			return strings.TrimSpace(authHeader[7:])
		}
	}
	return ""
}
