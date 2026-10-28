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

package audit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
)

func TestLoggerFunc(t *testing.T) {
	called := false
	var captured *audit.Entry

	fn := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		called = true
		captured = entry
		return nil
	})

	now := time.Now()
	entry := &audit.Entry{
		Timestamp:  now,
		UserID:     "alice@example.com",
		Provider:   "google",
		Agent:      "calendar_agent",
		Tool:       "read_calendar",
		Parameters: map[string]any{"date": "2026-10-01"},
		Action:     "token.access",
		Success:    true,
	}

	err := fn.LogAudit(context.Background(), entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Errorf("expected LoggerFunc to be called")
	}
	if captured.UserID != "alice@example.com" || captured.Tool != "read_calendar" {
		t.Errorf("unexpected entry captured: %+v", captured)
	}
}

func TestMultiLogger(t *testing.T) {
	count1 := 0
	count2 := 0
	expectedErr := errors.New("logger 2 failed")

	l1 := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		count1++
		return nil
	})
	l2 := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		count2++
		return expectedErr
	})

	multi := audit.MultiLogger{l1, nil, l2}
	err := multi.LogAudit(context.Background(), &audit.Entry{UserID: "test"})

	if count1 != 1 || count2 != 1 {
		t.Errorf("expected both loggers to be called once, got count1=%d, count2=%d", count1, count2)
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

func TestContextMerge(t *testing.T) {
	base := audit.Context{
		Agent: "agent1",
		Tool:  "tool1",
		Metadata: map[string]any{
			"env": "prod",
		},
	}

	other := audit.Context{
		Tool:       "tool2",
		Parameters: map[string]any{"arg": 123},
		Metadata: map[string]any{
			"trace_id": "xyz",
		},
	}

	merged := base.Merge(other)

	if merged.Agent != "agent1" {
		t.Errorf("expected Agent to be 'agent1', got %q", merged.Agent)
	}
	if merged.Tool != "tool2" {
		t.Errorf("expected Tool to be 'tool2', got %q", merged.Tool)
	}
	if merged.Parameters == nil {
		t.Fatalf("expected Parameters to be set")
	}
	if merged.Metadata["env"] != "prod" || merged.Metadata["trace_id"] != "xyz" {
		t.Errorf("unexpected Metadata: %+v", merged.Metadata)
	}
}

func TestDefaultLogger(t *testing.T) {
	orig := audit.DefaultLogger()
	defer audit.SetDefaultLogger(orig)

	called := false
	l := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		called = true
		return nil
	})

	audit.SetDefaultLogger(l)
	if audit.DefaultLogger() == nil {
		t.Fatalf("expected DefaultLogger to be non-nil")
	}

	_ = audit.DefaultLogger().LogAudit(context.Background(), &audit.Entry{})
	if !called {
		t.Errorf("expected default logger to be called")
	}
}

func TestDelegatedAuthProvider_AuditLogging_Success(t *testing.T) {
	store := auth.NewInMemoryStore()
	userID := "alice@example.com"
	_ = store.SetCredential(context.Background(), userID, "google", []byte("secret-token"))

	var loggedEntry *audit.Entry
	logger := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		loggedEntry = entry
		return nil
	})

	provider := store.DelegatedProvider(context.Background(), userID).
		WithAuditLogger(logger).
		WithAuditInfo("calendar_agent", "read_calendar", map[string]any{"date": "2026-10-01"})

	cred, err := provider.GetCredential(context.Background(), "google")
	if err != nil {
		t.Fatalf("unexpected error getting credential: %v", err)
	}
	if string(cred) != "secret-token" {
		t.Errorf("expected secret-token, got %s", string(cred))
	}

	if loggedEntry == nil {
		t.Fatalf("expected audit entry to be logged")
	}
	if loggedEntry.UserID != userID {
		t.Errorf("expected UserID %q, got %q", userID, loggedEntry.UserID)
	}
	if loggedEntry.Provider != "google" {
		t.Errorf("expected Provider 'google', got %q", loggedEntry.Provider)
	}
	if loggedEntry.Agent != "calendar_agent" {
		t.Errorf("expected Agent 'calendar_agent', got %q", loggedEntry.Agent)
	}
	if loggedEntry.Tool != "read_calendar" {
		t.Errorf("expected Tool 'read_calendar', got %q", loggedEntry.Tool)
	}
	if !loggedEntry.Success {
		t.Errorf("expected Success true, got false")
	}
	params, ok := loggedEntry.Parameters.(map[string]any)
	if !ok || params["date"] != "2026-10-01" {
		t.Errorf("unexpected Parameters: %+v", loggedEntry.Parameters)
	}
}

func TestDelegatedAuthProvider_AuditLogging_Failure(t *testing.T) {
	store := auth.NewInMemoryStore()
	userID := "bob@example.com"

	var loggedEntry *audit.Entry
	logger := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		loggedEntry = entry
		return nil
	})

	provider := store.DelegatedProvider(context.Background(), userID).
		WithAuditLogger(logger).
		WithAuditInfo("git_agent", "clone", nil)

	_, err := provider.GetCredential(context.Background(), "github")
	if err == nil {
		t.Fatalf("expected error for missing credential")
	}

	if loggedEntry == nil {
		t.Fatalf("expected audit entry to be logged")
	}
	if loggedEntry.Success {
		t.Errorf("expected Success false, got true")
	}
	if loggedEntry.Error == "" {
		t.Errorf("expected Error string to be populated")
	}
	if loggedEntry.Agent != "git_agent" || loggedEntry.Tool != "clone" {
		t.Errorf("unexpected agent/tool: %+v", loggedEntry)
	}
}

func TestDelegatedAuthProvider_StrictAudit(t *testing.T) {
	store := auth.NewInMemoryStore()
	userID := "alice@example.com"
	_ = store.SetCredential(context.Background(), userID, "google", []byte("token"))

	loggerErr := errors.New("audit log write failed")
	failingLogger := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		return loggerErr
	})

	// Fail-open by default
	providerFailOpen := store.DelegatedProvider(context.Background(), userID).
		WithAuditLogger(failingLogger)

	cred, err := providerFailOpen.GetCredential(context.Background(), "google")
	if err != nil {
		t.Fatalf("expected fail-open to succeed despite logger failure, got %v", err)
	}
	if string(cred) != "token" {
		t.Errorf("expected token, got %s", string(cred))
	}

	// Fail-closed with StrictAudit
	providerFailClosed := store.DelegatedProvider(context.Background(), userID).
		WithAuditLogger(failingLogger).
		WithStrictAudit(true)

	_, err = providerFailClosed.GetCredential(context.Background(), "google")
	if err == nil {
		t.Fatalf("expected strict audit to fail credential access when logger fails")
	}
	if !errors.Is(err, loggerErr) {
		t.Errorf("expected error to wrap %v, got %v", loggerErr, err)
	}
}

func TestInMemoryStore_AuditLoggerConfiguration(t *testing.T) {
	store := auth.NewInMemoryStore()
	called := false
	logger := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		called = true
		return nil
	})

	store.SetAuditLogger(logger)
	store.SetStrictAudit(true)

	_ = store.SetCredential(context.Background(), "user1", "google", []byte("tok"))
	provider := store.DelegatedProvider(context.Background(), "user1")

	_, err := provider.GetCredential(context.Background(), "google")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Errorf("expected logger configured on store to be invoked")
	}
}

func TestAuthRoundTripper_AuditHTTPMetadata(t *testing.T) {
	store := auth.NewInMemoryStore()
	userID := "alice@example.com"
	_ = store.SetCredential(context.Background(), userID, "google", []byte("oauth-token"))

	var capturedEntry *audit.Entry
	logger := audit.LoggerFunc(func(ctx context.Context, entry *audit.Entry) error {
		capturedEntry = entry
		return nil
	})

	provider := store.DelegatedProvider(context.Background(), userID).
		WithAuditLogger(logger).
		WithAuditInfo("calendar_agent", "read_calendar", nil)

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer oauth-token" {
			t.Errorf("expected Bearer oauth-token, got %s", authHeader)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rt := &auth.AuthRoundTripper{
		RoundTripper: http.DefaultTransport,
		AuthProvider: "google",
	}

	req, _ := http.NewRequestWithContext(
		auth.WithDelegatedAuthProvider(context.Background(), provider),
		http.MethodPost,
		server.URL+"/events",
		nil,
	)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if capturedEntry == nil {
		t.Fatalf("expected audit entry to be recorded")
	}
	if capturedEntry.Agent != "calendar_agent" || capturedEntry.Tool != "read_calendar" {
		t.Errorf("unexpected agent/tool: %+v", capturedEntry)
	}
	if capturedEntry.Metadata["http.method"] != http.MethodPost {
		t.Errorf("expected http.method POST, got %v", capturedEntry.Metadata["http.method"])
	}
	if capturedEntry.Metadata["http.url"] != server.URL+"/events" {
		t.Errorf("expected http.url %s/events, got %v", server.URL, capturedEntry.Metadata["http.url"])
	}
}
