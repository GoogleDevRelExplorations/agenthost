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

package providers

import (
	"context"
	"sync"

	"golang.org/x/oauth2"
)

// SigninProvider abstracts authentication and UserID resolution for sign-in.
type SigninProvider interface {
	Name() string
	Endpoint() oauth2.Endpoint
	DefaultScopes() []string
	UserID(ctx context.Context, tok *oauth2.Token) (string, error)
}

var (
	signinMu        sync.RWMutex
	signinProviders = make(map[string]SigninProvider)
)

// RegisterSigninProvider registers a sign-in provider.
func RegisterSigninProvider(p SigninProvider) {
	signinMu.Lock()
	defer signinMu.Unlock()
	signinProviders[p.Name()] = p
}

// GetSigninProvider retrieves a sign-in provider by name.
func GetSigninProvider(name string) (SigninProvider, bool) {
	signinMu.RLock()
	defer signinMu.RUnlock()
	p, ok := signinProviders[name]
	return p, ok
}

// ListSigninProviders returns all registered sign-in providers.
func ListSigninProviders() []SigninProvider {
	signinMu.RLock()
	defer signinMu.RUnlock()
	var list []SigninProvider
	for _, p := range signinProviders {
		list = append(list, p)
	}
	return list
}
