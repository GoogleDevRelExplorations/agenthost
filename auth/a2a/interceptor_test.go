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
	"net/http"
	"testing"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"google.golang.org/api/idtoken"
)

func mockValidator(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	if token == "valid-a2a-token" {
		return &idtoken.Payload{
			Claims: map[string]any{
				"email": "a2a-user@example.com",
			},
		}, nil
	}
	return nil, fmt.Errorf("invalid token: %s", token)
}

func TestA2AInterceptor_Authenticated(t *testing.T) {
	credStore := auth.NewInMemoryStore()
	interceptor := &AuthInterceptor{
		Store:     credStore,
		Audience:  "test-aud",
		Validator: mockValidator,
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer valid-a2a-token")
	serviceParams := a2asrv.NewServiceParams(headers)

	_, callCtx := a2asrv.NewCallContext(context.Background(), serviceParams)

	ctx, _, err := interceptor.Before(context.Background(), callCtx, nil)
	if err != nil {
		t.Fatalf("Interceptor Before returned error: %v", err)
	}

	if callCtx.User == nil || !callCtx.User.Authenticated || callCtx.User.Name != "a2a-user@example.com" {
		t.Errorf("Expected authenticated user a2a-user@example.com, got: %+v", callCtx.User)
	}

	provider, ok := auth.DelegatedAuthProviderFrom(ctx)
	if !ok || provider == nil {
		t.Errorf("Expected DelegatedAuthProvider in context")
	} else if provider.Email() != "a2a-user@example.com" {
		t.Errorf("Expected provider email a2a-user@example.com, got %s", provider.Email())
	}
}

func TestA2AInterceptor_Unauthenticated(t *testing.T) {
	credStore := auth.NewInMemoryStore()
	interceptor := NewAuthInterceptor(credStore)

	_, callCtx := a2asrv.NewCallContext(context.Background(), a2asrv.NewServiceParams(http.Header{}))

	ctx, _, err := interceptor.Before(context.Background(), callCtx, nil)
	if err != nil {
		t.Fatalf("Interceptor Before returned error: %v", err)
	}

	if callCtx.User != nil && callCtx.User.Authenticated {
		t.Errorf("Expected callCtx.User to not be authenticated for anonymous call, got: %+v", callCtx.User)
	}

	provider, ok := auth.DelegatedAuthProviderFrom(ctx)
	if ok || provider != nil {
		t.Errorf("Expected no DelegatedAuthProvider in context")
	}
}
