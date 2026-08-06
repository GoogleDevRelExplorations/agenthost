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
	"sync"
)

// Store defines the interface for storing and retrieving user session ID tokens.
type Store interface {
	GetIDToken(ctx context.Context, sessionID string) (string, error)
	SetIDToken(ctx context.Context, sessionID string, idToken string) error
	DeleteSession(ctx context.Context, sessionID string) error
}

// InMemoryStore is a thread-safe, in-memory implementation of Store.
type InMemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]string
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		sessions: make(map[string]string),
	}
}

// GetIDToken retrieves the ID token associated with the sessionID.
func (s *InMemoryStore) GetIDToken(ctx context.Context, sessionID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idToken, ok := s.sessions[sessionID]
	if !ok {
		return "", fmt.Errorf("session not found")
	}
	return idToken, nil
}

// SetIDToken maps the sessionID to the given idToken.
func (s *InMemoryStore) SetIDToken(ctx context.Context, sessionID string, idToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = idToken
	return nil
}

// DeleteSession removes the session mapping.
func (s *InMemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}
