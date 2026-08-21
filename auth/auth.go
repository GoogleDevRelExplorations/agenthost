// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under/the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
)

// CredentialStore defines the interface for storing and retrieving opaque credentials.
type CredentialStore interface {
	GetCredential(ctx context.Context, email string, provider string) ([]byte, error)
	SetCredential(ctx context.Context, email string, provider string, cred []byte) error
	DelegatedProvider(ctx context.Context, email string) *DelegatedAuthProvider
}

// InMemoryStore is an in-memory implementation of CredentialStore.
type InMemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]map[string][]byte
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		credentials: make(map[string]map[string][]byte),
	}
}

// GetCredential retrieves a credential from memory.
func (s *InMemoryStore) GetCredential(ctx context.Context, email string, provider string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userCreds, ok := s.credentials[email]
	if !ok {
		return nil, fmt.Errorf("no credentials found for user: %s", email)
	}
	cred, ok := userCreds[provider]
	if !ok {
		return nil, fmt.Errorf("credential not found for provider %s and user %s", provider, email)
	}
	return cred, nil
}

// SetCredential stores a credential in memory.
func (s *InMemoryStore) SetCredential(ctx context.Context, email string, provider string, cred []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userCreds, ok := s.credentials[email]
	if !ok {
		userCreds = make(map[string][]byte)
		s.credentials[email] = userCreds
	}
	userCreds[provider] = cred
	return nil
}

// GetCredentials returns a copy of all credentials for a given user email.
func (s *InMemoryStore) GetCredentials(ctx context.Context, email string) map[string][]byte {
	cmap := make(map[string][]byte)
	s.mu.Lock()
	defer s.mu.Unlock()
	if src, ok := s.credentials[email]; ok {
		maps.Copy(cmap, src)
	}
	return cmap
}

// DelegatedProvider returns a user-scoped DelegatedAuthProvider.
func (s *InMemoryStore) DelegatedProvider(ctx context.Context, email string) *DelegatedAuthProvider {
	return NewDelegatedAuthProvider(s, email)
}

// DelegatedAuthProvider provides access to delegated credentials scoped to the authenticated user.
type DelegatedAuthProvider struct {
	store CredentialStore
	email string
}

// NewDelegatedAuthProvider creates a new DelegatedAuthProvider scoped to a user email and backed by a CredentialStore.
func NewDelegatedAuthProvider(store CredentialStore, email string) *DelegatedAuthProvider {
	return &DelegatedAuthProvider{
		store: store,
		email: email,
	}
}

// GetCredential retrieves the delegated credential for the specified provider for the authenticated user.
func (p *DelegatedAuthProvider) GetCredential(ctx context.Context, provider string) ([]byte, error) {
	if p == nil || p.store == nil {
		return nil, fmt.Errorf("credential store not configured")
	}
	return p.store.GetCredential(ctx, p.email, provider)
}

// Providers returns the list of registered provider names that have delegated credentials or are registered.
func (p *DelegatedAuthProvider) Providers() []string {
	var names []string
	for _, prov := range registry.ListProviders() {
		names = append(names, prov.Name)
	}
	return names
}

// Email returns the authenticated user's email.
func (p *DelegatedAuthProvider) Email() string {
	if p == nil {
		return ""
	}
	return p.email
}

type contextKey struct{}

var providerContextKey = contextKey{}

// WithDelegatedAuthProvider returns a new context containing the specified DelegatedAuthProvider.
func WithDelegatedAuthProvider(ctx context.Context, provider *DelegatedAuthProvider) context.Context {
	return context.WithValue(ctx, providerContextKey, provider)
}

// DelegatedAuthProviderFrom retrieves the DelegatedAuthProvider from the context, if present.
func DelegatedAuthProviderFrom(ctx context.Context) (*DelegatedAuthProvider, bool) {
	p, ok := ctx.Value(providerContextKey).(*DelegatedAuthProvider)
	return p, ok
}
