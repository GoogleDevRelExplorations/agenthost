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

	"github.com/spf13/viper"
	"google.golang.org/api/idtoken"
)

// ValidatorFunc validates an OIDC ID token string against an expected audience.
type ValidatorFunc func(ctx context.Context, token string, audience string) (*idtoken.Payload, error)

// ValidateIDToken validates an ID token and extracts the user's email and claims.
// If audience is empty, it falls back to viper config "oauth.google.client_id".
func ValidateIDToken(ctx context.Context, token string, audience string, validator ValidatorFunc) (string, map[string]any, error) {
	if token == "" {
		return "", nil, fmt.Errorf("token is empty")
	}
	if validator == nil {
		validator = idtoken.Validate
	}
	if audience == "" {
		audience = viper.GetString("oauth.google.client_id")
	}

	payload, err := validator(ctx, token, audience)
	if err != nil {
		return "", nil, fmt.Errorf("invalid OIDC credential: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	if email == "" {
		return "", nil, fmt.Errorf("invalid OIDC payload: missing email claim")
	}

	return email, payload.Claims, nil
}
