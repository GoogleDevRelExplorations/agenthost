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

package slogaudit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
	slogaudit "github.com/GoogleDevRelExplorations/agenthost/auth/audit/slog"
)

func TestSlogLogger_Success(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	sl := slog.New(handler)
	l := slogaudit.New(sl, slogaudit.WithLevel(slog.LevelInfo))

	entry := &audit.Entry{
		Timestamp:  time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		UserID:     "alice@example.com",
		Provider:   "google",
		Agent:      "calendar_agent",
		Tool:       "read_calendar",
		Parameters: map[string]any{"date": "2026-10-01"},
		Action:     "token.access",
		Success:    true,
		Metadata:   map[string]any{"http.method": "GET"},
	}

	err := l.LogAudit(context.Background(), entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse log JSON: %v, raw: %s", err, buf.String())
	}

	if parsed["level"] != "INFO" {
		t.Errorf("expected level INFO, got %v", parsed["level"])
	}
	if parsed["user_id"] != "alice@example.com" {
		t.Errorf("expected user_id alice@example.com, got %v", parsed["user_id"])
	}
	if parsed["provider"] != "google" {
		t.Errorf("expected provider google, got %v", parsed["provider"])
	}
	if parsed["agent"] != "calendar_agent" {
		t.Errorf("expected agent calendar_agent, got %v", parsed["agent"])
	}
	if parsed["tool"] != "read_calendar" {
		t.Errorf("expected tool read_calendar, got %v", parsed["tool"])
	}
	if parsed["success"] != true {
		t.Errorf("expected success true, got %v", parsed["success"])
	}
	params, ok := parsed["parameters"].(map[string]any)
	if !ok || params["date"] != "2026-10-01" {
		t.Errorf("expected parameters.date = '2026-10-01', got %v", parsed["parameters"])
	}
}

func TestSlogLogger_Failure(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	sl := slog.New(handler)
	l := slogaudit.New(sl)

	entry := &audit.Entry{
		Timestamp: time.Now(),
		UserID:    "bob@example.com",
		Provider:  "github",
		Agent:     "git_agent",
		Tool:      "clone_repo",
		Action:    "token.access",
		Success:   false,
		Error:     "credential not found",
	}

	err := l.LogAudit(context.Background(), entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse log JSON: %v, raw: %s", err, buf.String())
	}

	if parsed["level"] != "ERROR" {
		t.Errorf("expected level ERROR for failed audit entry, got %v", parsed["level"])
	}
	if parsed["error"] != "credential not found" {
		t.Errorf("expected error string in log, got %v", parsed["error"])
	}
}
