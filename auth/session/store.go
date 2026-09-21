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

	"github.com/GoogleDevRelExplorations/agenthost/auth"
)

// SessionData aliases auth.SessionData.
type SessionData = auth.SessionData

// SessionStore aliases auth.SessionStore.
type SessionStore = auth.SessionStore

// InMemoryStore is a thread-safe, in-memory implementation of SessionStore.
type InMemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionData
}

// NewInMemoryStore creates a new InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		sessions: make(map[string]*SessionData),
	}
}

// GetSession retrieves the SessionData associated with the sessionID.
func (s *InMemoryStore) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return sess, nil
}

// SetSession maps the sessionID to the given SessionData.
func (s *InMemoryStore) SetSession(ctx context.Context, sess *SessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sess.ID] = sess
	return nil
}

// DeleteSession removes the session mapping.
func (s *InMemoryStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
	return nil
}

// GetUserID returns the UserID associated with the given sessionID.
func (s *InMemoryStore) GetUserID(ctx context.Context, sessionID string) (string, error) {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	return sess.UserID, nil
}

