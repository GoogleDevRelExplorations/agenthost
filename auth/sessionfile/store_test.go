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
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"golang.org/x/oauth2"
)

func TestNew_EmptyPath(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatalf("expected error for empty filePath, got nil")
	}
}

func TestNew_NonExistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sub", "sessions.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	_, err = store.GetSession(context.Background(), "unknown")
	if err == nil {
		t.Fatalf("expected error getting unknown session, got nil")
	}
}

func TestSetAndGetSession(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)
	sess := &auth.SessionData{
		ID:        "sess-123",
		UserID:    "user@example.com",
		Provider:  "google",
		Token: &oauth2.Token{
			AccessToken:  "access-token-xyz",
			TokenType:    "Bearer",
			RefreshToken: "refresh-token-xyz",
			Expiry:       now.Add(time.Hour),
		},
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}

	if err := store.SetSession(ctx, sess); err != nil {
		t.Fatalf("SetSession failed: %v", err)
	}

	got, err := store.GetSession(ctx, "sess-123")
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if got.ID != sess.ID {
		t.Errorf("expected ID %s, got %s", sess.ID, got.ID)
	}
	if got.UserID != sess.UserID {
		t.Errorf("expected UserID %s, got %s", sess.UserID, got.UserID)
	}
	if got.Provider != sess.Provider {
		t.Errorf("expected Provider %s, got %s", sess.Provider, got.Provider)
	}
	if got.Token == nil || got.Token.AccessToken != "access-token-xyz" {
		t.Errorf("unexpected token in session: %+v", got.Token)
	}
}

func TestGetUserID(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	_, err = store.GetUserID(ctx, "nonexistent")
	if err == nil {
		t.Fatalf("expected error for nonexistent session, got nil")
	}

	sess := &auth.SessionData{
		ID:     "s1",
		UserID: "octocat",
	}
	if err := store.SetSession(ctx, sess); err != nil {
		t.Fatalf("SetSession failed: %v", err)
	}

	uid, err := store.GetUserID(ctx, "s1")
	if err != nil {
		t.Fatalf("GetUserID failed: %v", err)
	}
	if uid != "octocat" {
		t.Errorf("expected UserID 'octocat', got '%s'", uid)
	}
}

func TestDeleteSession(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	sess := &auth.SessionData{
		ID:     "s1",
		UserID: "octocat",
	}
	if err := store.SetSession(ctx, sess); err != nil {
		t.Fatalf("SetSession failed: %v", err)
	}

	if err := store.DeleteSession(ctx, "s1"); err != nil {
		t.Fatalf("DeleteSession failed: %v", err)
	}

	_, err = store.GetSession(ctx, "s1")
	if err == nil {
		t.Fatalf("expected error after deleting session, got nil")
	}
}

func TestPersistenceAcrossInstances(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	ctx := context.Background()

	// Instance 1: write session
	store1, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store1: %v", err)
	}
	sess := &auth.SessionData{
		ID:     "sess-persisted",
		UserID: "persisted-user",
	}
	if err := store1.SetSession(ctx, sess); err != nil {
		t.Fatalf("SetSession in store1 failed: %v", err)
	}

	// Instance 2: reload from disk
	store2, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store2: %v", err)
	}
	got, err := store2.GetSession(ctx, "sess-persisted")
	if err != nil {
		t.Fatalf("GetSession in store2 failed: %v", err)
	}
	if got.UserID != "persisted-user" {
		t.Errorf("expected UserID 'persisted-user', got '%s'", got.UserID)
	}

	// Instance 2: delete session
	if err := store2.DeleteSession(ctx, "sess-persisted"); err != nil {
		t.Fatalf("DeleteSession in store2 failed: %v", err)
	}

	// Instance 3: reload from disk and verify deletion
	store3, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store3: %v", err)
	}
	_, err = store3.GetSession(ctx, "sess-persisted")
	if err == nil {
		t.Fatalf("expected session to be deleted in store3, got nil error")
	}
}

func TestCorruptJSONFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	if err := os.WriteFile(filePath, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("failed to write corrupt json: %v", err)
	}

	_, err := New(filePath)
	if err == nil {
		t.Fatalf("expected error loading corrupt json file, got nil")
	}
}

func TestEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	if err := os.WriteFile(filePath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("expected New on empty file to succeed, got %v", err)
	}

	_, err = store.GetSession(context.Background(), "s1")
	if err == nil {
		t.Fatalf("expected error on empty store, got nil")
	}
}

func TestConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sessions.json")

	store, err := New(filePath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	var wg sync.WaitGroup
	workers := 10
	iterations := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				id := fmt.Sprintf("worker-%d-sess-%d", workerID, j)
				sess := &auth.SessionData{
					ID:     id,
					UserID: fmt.Sprintf("user-%d", workerID),
				}
				if err := store.SetSession(ctx, sess); err != nil {
					t.Errorf("concurrent SetSession error: %v", err)
				}
				if _, err := store.GetSession(ctx, id); err != nil {
					t.Errorf("concurrent GetSession error: %v", err)
				}
				if _, err := store.GetUserID(ctx, id); err != nil {
					t.Errorf("concurrent GetUserID error: %v", err)
				}
				if j%2 == 0 {
					if err := store.DeleteSession(ctx, id); err != nil {
						t.Errorf("concurrent DeleteSession error: %v", err)
					}
				}
			}
		}(i)
	}

	wg.Wait()
}
