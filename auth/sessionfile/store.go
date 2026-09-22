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

package sessionfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
)

var _ auth.SessionStore = (*FileSessionStore)(nil)

// FileSessionStore is a thread-safe implementation of auth.SessionStore backed by a local JSON file.
type FileSessionStore struct {
	filePath string
	mu       sync.RWMutex
	sessions map[string]*auth.SessionData
}

// New creates a new FileSessionStore. It loads any existing sessions from filePath.
// If the file does not exist, it will be created upon first write.
func New(filePath string) (*FileSessionStore, error) {
	if filePath == "" {
		return nil, errors.New("filePath cannot be empty")
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for session file: %w", err)
	}

	store := &FileSessionStore{
		filePath: filePath,
		sessions: make(map[string]*auth.SessionData),
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	if len(data) == 0 {
		return store, nil
	}

	if err := json.Unmarshal(data, &store.sessions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sessions from file: %w", err)
	}

	return store, nil
}

// GetSession retrieves the SessionData associated with the sessionID.
func (s *FileSessionStore) GetSession(ctx context.Context, sessionID string) (*auth.SessionData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return sess, nil
}

// SetSession stores or updates the SessionData and persists the store to disk.
func (s *FileSessionStore) SetSession(ctx context.Context, sess *auth.SessionData) error {
	if sess == nil {
		return errors.New("session cannot be nil")
	}
	if sess.ID == "" {
		return errors.New("session ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[sess.ID] = sess
	return s.saveLocked()
}

// DeleteSession removes the session mapping and persists the changes to disk.
func (s *FileSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return s.saveLocked()
}

// GetUserID returns the UserID associated with the given sessionID.
func (s *FileSessionStore) GetUserID(ctx context.Context, sessionID string) (string, error) {
	sess, err := s.GetSession(ctx, sessionID)
	if err != nil {
		return "", err
	}
	return sess.UserID, nil
}

// saveLocked writes the sessions to disk atomically. Caller must hold s.mu.Lock().
func (s *FileSessionStore) saveLocked() error {
	data, err := json.MarshalIndent(s.sessions, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal sessions: %w", err)
	}

	dir := filepath.Dir(s.filePath)
	tmpFile, err := os.CreateTemp(dir, "sessions-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file for session save: %w", err)
	}
	tmpName := tmpFile.Name()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to write to temporary session file: %w", err)
	}

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close temporary session file: %w", err)
	}

	if err := os.Rename(tmpName, s.filePath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to replace session file: %w", err)
	}

	return nil
}
