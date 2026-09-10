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

package auth

import (
	"context"
	"fmt"
	"testing"

	"github.com/spf13/viper"
	"google.golang.org/api/idtoken"
)

func TestValidateIDToken_Success(t *testing.T) {
	ctx := context.Background()
	mockValidator := func(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
		if token != "valid-token" {
			return nil, fmt.Errorf("invalid token")
		}
		if audience != "test-aud" {
			return nil, fmt.Errorf("invalid audience: %s", audience)
		}
		return &idtoken.Payload{
			Claims: map[string]any{
				"email": "user@example.com",
				"sub":   "12345",
			},
		}, nil
	}

	email, claims, err := ValidateIDToken(ctx, "valid-token", "test-aud", mockValidator)
	if err != nil {
		t.Fatalf("ValidateIDToken failed: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", email)
	}
	if claims["sub"] != "12345" {
		t.Errorf("Expected sub 12345, got %v", claims["sub"])
	}
}

func TestValidateIDToken_ViperAudienceFallback(t *testing.T) {
	ctx := context.Background()
	viper.Set("oauth.google.client_id", "fallback-client-id")
	defer viper.Set("oauth.google.client_id", "")

	mockValidator := func(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
		if audience != "fallback-client-id" {
			return nil, fmt.Errorf("expected audience fallback-client-id, got %s", audience)
		}
		return &idtoken.Payload{
			Claims: map[string]any{
				"email": "user@example.com",
			},
		}, nil
	}

	email, _, err := ValidateIDToken(ctx, "any-token", "", mockValidator)
	if err != nil {
		t.Fatalf("ValidateIDToken with fallback audience failed: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("Expected email user@example.com, got %s", email)
	}
}

func TestValidateIDToken_EmptyToken(t *testing.T) {
	ctx := context.Background()
	_, _, err := ValidateIDToken(ctx, "", "test-aud", nil)
	if err == nil {
		t.Errorf("Expected error for empty token, got nil")
	}
}

func TestValidateIDToken_MissingEmailClaim(t *testing.T) {
	ctx := context.Background()
	mockValidator := func(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
		return &idtoken.Payload{
			Claims: map[string]any{
				"sub": "12345",
			},
		}, nil
	}

	_, _, err := ValidateIDToken(ctx, "valid-token", "test-aud", mockValidator)
	if err == nil {
		t.Errorf("Expected error for missing email claim, got nil")
	}
}
