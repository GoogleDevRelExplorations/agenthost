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
	"maps"
	"sync"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"golang.org/x/oauth2"
)

// SessionData holds session state including the authenticated user ID and OAuth tokens.
type SessionData struct {
	ID        string        `json:"id"`
	UserID    string        `json:"user_id"`
	Provider  string        `json:"provider"`
	Token     *oauth2.Token `json:"token,omitempty"`
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// SessionStore defines the interface for storing and retrieving user sessions.
type SessionStore interface {
	GetSession(ctx context.Context, sessionID string) (*SessionData, error)
	SetSession(ctx context.Context, session *SessionData) error
	DeleteSession(ctx context.Context, sessionID string) error
	GetUserID(ctx context.Context, sessionID string) (string, error)
}

// CredentialStore defines the interface for storing and retrieving opaque credentials.
type CredentialStore interface {
	GetCredential(ctx context.Context, userID string, provider string) ([]byte, error)
	SetCredential(ctx context.Context, userID string, provider string, cred []byte) error
	DelegatedProvider(ctx context.Context, userID string) *DelegatedAuthProvider
}

// InMemoryStore is an in-memory implementation of CredentialStore.
type InMemoryStore struct {
	mu          sync.RWMutex
	credentials map[string]map[string][]byte
	auditLogger audit.Logger
	strictAudit bool
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		credentials: make(map[string]map[string][]byte),
	}
}

// SetAuditLogger configures the default audit logger for DelegatedAuthProviders created by this store.
func (s *InMemoryStore) SetAuditLogger(logger audit.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogger = logger
}

// SetStrictAudit configures whether failed audit log writes fail credential retrieval.
func (s *InMemoryStore) SetStrictAudit(strict bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.strictAudit = strict
}

// GetCredential retrieves a credential from memory.
func (s *InMemoryStore) GetCredential(ctx context.Context, userID string, provider string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	userCreds, ok := s.credentials[userID]
	if !ok {
		return nil, fmt.Errorf("no credentials found for user: %s", userID)
	}
	cred, ok := userCreds[provider]
	if !ok {
		return nil, fmt.Errorf("credential not found for provider %s and user %s", provider, userID)
	}
	return cred, nil
}

// SetCredential stores a credential in memory.
func (s *InMemoryStore) SetCredential(ctx context.Context, userID string, provider string, cred []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	userCreds, ok := s.credentials[userID]
	if !ok {
		userCreds = make(map[string][]byte)
		s.credentials[userID] = userCreds
	}
	userCreds[provider] = cred
	return nil
}

// GetCredentials returns a copy of all credentials for a given user.
func (s *InMemoryStore) GetCredentials(ctx context.Context, userID string) map[string][]byte {
	cmap := make(map[string][]byte)
	s.mu.Lock()
	defer s.mu.Unlock()
	if src, ok := s.credentials[userID]; ok {
		maps.Copy(cmap, src)
	}
	return cmap
}

// DelegatedProvider returns a user-scoped DelegatedAuthProvider.
func (s *InMemoryStore) DelegatedProvider(ctx context.Context, userID string) *DelegatedAuthProvider {
	s.mu.RLock()
	logger := s.auditLogger
	strict := s.strictAudit
	s.mu.RUnlock()

	p := NewDelegatedAuthProvider(s, userID)
	if logger != nil {
		p = p.WithAuditLogger(logger)
	}
	if strict {
		p = p.WithStrictAudit(strict)
	}
	return p
}

// DelegatedAuthProvider provides access to delegated credentials scoped to the authenticated user.
type DelegatedAuthProvider struct {
	store       CredentialStore
	userID      string
	auditLogger audit.Logger
	auditCtx    audit.Context
	strictAudit bool
}

// NewDelegatedAuthProvider creates a new DelegatedAuthProvider scoped to a user ID and backed by a CredentialStore.
func NewDelegatedAuthProvider(store CredentialStore, userID string) *DelegatedAuthProvider {
	return &DelegatedAuthProvider{
		store:       store,
		userID:      userID,
		auditLogger: audit.DefaultLogger(),
	}
}

// WithAudit returns a shallow copy of the provider with additional audit context merged in.
func (p *DelegatedAuthProvider) WithAudit(ac audit.Context) *DelegatedAuthProvider {
	cp := *p
	cp.auditCtx = p.auditCtx.Merge(ac)
	return &cp
}

// WithAuditInfo is a convenience helper for setting agent, tool, and parameters.
func (p *DelegatedAuthProvider) WithAuditInfo(agent, tool string, params any) *DelegatedAuthProvider {
	return p.WithAudit(audit.Context{
		Agent:      agent,
		Tool:       tool,
		Parameters: params,
	})
}

// WithAuditLogger returns a shallow copy of the provider configured with the given AuditLogger.
func (p *DelegatedAuthProvider) WithAuditLogger(logger audit.Logger) *DelegatedAuthProvider {
	cp := *p
	cp.auditLogger = logger
	return &cp
}

// WithStrictAudit returns a shallow copy of the provider configured with the given strict audit policy.
func (p *DelegatedAuthProvider) WithStrictAudit(strict bool) *DelegatedAuthProvider {
	cp := *p
	cp.strictAudit = strict
	return &cp
}

// GetCredential retrieves the delegated credential for the specified provider for the authenticated user.
func (p *DelegatedAuthProvider) GetCredential(ctx context.Context, provider string) ([]byte, error) {
	if p == nil || p.store == nil {
		return nil, fmt.Errorf("credential store not configured")
	}

	cred, err := p.store.GetCredential(ctx, p.userID, provider)

	logger := p.auditLogger
	if logger == nil {
		logger = audit.DefaultLogger()
	}

	if logger != nil {
		entry := &audit.Entry{
			Timestamp:  time.Now(),
			UserID:     p.userID,
			Provider:   provider,
			Agent:      p.auditCtx.Agent,
			Tool:       p.auditCtx.Tool,
			Parameters: p.auditCtx.Parameters,
			Action:     "token.access",
			Success:    err == nil,
			Metadata:   p.auditCtx.Metadata,
		}
		if err != nil {
			entry.Error = err.Error()
		}

		if logErr := logger.LogAudit(ctx, entry); logErr != nil {
			if p.strictAudit {
				return nil, fmt.Errorf("audit logging failed: %w", logErr)
			}
		}
	}

	return cred, err
}

// Providers returns the list of registered provider names that have delegated credentials or are registered.
func (p *DelegatedAuthProvider) Providers() []string {
	var names []string
	for _, prov := range registry.ListProviders() {
		names = append(names, prov.Name)
	}
	return names
}

// UserID returns the authenticated user's ID.
func (p *DelegatedAuthProvider) UserID() string {
	if p == nil {
		return ""
	}
	return p.userID
}

// Email returns the authenticated user's ID (alias for UserID for backward compatibility).
func (p *DelegatedAuthProvider) Email() string {
	return p.UserID()
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

type AuthRequiredError struct {
	provider string
}

func (e AuthRequiredError) Error() string {
	return fmt.Sprintf("Auth required. go to http://localhost:9001/authorize/%s to grant.", e.provider)
}
