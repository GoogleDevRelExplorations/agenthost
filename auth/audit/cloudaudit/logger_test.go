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

package cloudaudit_test

import (
	"context"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
	"github.com/GoogleDevRelExplorations/agenthost/auth/audit/cloudaudit"
)

type mockClient struct {
	lastLogName string
	lastEntry   cloudaudit.Entry
	closed      bool
}

func (m *mockClient) Log(ctx context.Context, logName string, entry cloudaudit.Entry) error {
	m.lastLogName = logName
	m.lastEntry = entry
	return nil
}

func (m *mockClient) Close() error {
	m.closed = true
	return nil
}

func TestCloudAuditLogger_Success(t *testing.T) {
	client := &mockClient{}
	logger, err := cloudaudit.New(cloudaudit.Config{
		ProjectID: "my-gcp-project",
		Client:    client,
	})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}

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
		Metadata:   map[string]any{"caller_ip": "127.0.0.1"},
	}

	if err := logger.LogAudit(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error from LogAudit: %v", err)
	}

	if client.lastLogName != cloudaudit.DefaultLogName {
		t.Errorf("expected log name %q, got %q", cloudaudit.DefaultLogName, client.lastLogName)
	}
	if client.lastEntry.Severity != "INFO" {
		t.Errorf("expected severity INFO, got %q", client.lastEntry.Severity)
	}

	payload, ok := client.lastEntry.Payload.(cloudaudit.CloudAuditLogPayload)
	if !ok {
		t.Fatalf("expected payload of type CloudAuditLogPayload, got %T", client.lastEntry.Payload)
	}

	if payload.ServiceName != cloudaudit.DefaultServiceName {
		t.Errorf("expected serviceName %q, got %q", cloudaudit.DefaultServiceName, payload.ServiceName)
	}
	if payload.MethodName != "google.read_calendar" {
		t.Errorf("expected methodName 'google.read_calendar', got %q", payload.MethodName)
	}
	expectedResource := "projects/my-gcp-project/users/alice@example.com/providers/google"
	if payload.ResourceName != expectedResource {
		t.Errorf("expected resourceName %q, got %q", expectedResource, payload.ResourceName)
	}
	if payload.AuthenticationInfo["principalEmail"] != "alice@example.com" {
		t.Errorf("expected principalEmail alice@example.com, got %v", payload.AuthenticationInfo["principalEmail"])
	}
	if payload.Request["agent"] != "calendar_agent" || payload.Request["tool"] != "read_calendar" {
		t.Errorf("unexpected request payload: %+v", payload.Request)
	}
	if payload.Status["code"] != 0 || payload.Status["message"] != "OK" {
		t.Errorf("expected OK status, got %+v", payload.Status)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("unexpected error closing logger: %v", err)
	}
	if !client.closed {
		t.Errorf("expected client to be closed")
	}
}

func TestCloudAuditLogger_Failure(t *testing.T) {
	client := &mockClient{}
	customLog := "projects/my-gcp-project/logs/custom-audit"
	customService := "custom.auth"
	logger, err := cloudaudit.New(cloudaudit.Config{
		ProjectID:   "my-gcp-project",
		LogName:     customLog,
		ServiceName: customService,
		Client:      client,
	})
	if err != nil {
		t.Fatalf("unexpected error creating logger: %v", err)
	}

	entry := &audit.Entry{
		Timestamp: time.Now(),
		UserID:    "bob@example.com",
		Provider:  "github",
		Agent:     "git_agent",
		Tool:      "clone",
		Action:    "token.access",
		Success:   false,
		Error:     "permission denied",
	}

	if err := logger.LogAudit(context.Background(), entry); err != nil {
		t.Fatalf("unexpected error from LogAudit: %v", err)
	}

	if client.lastLogName != customLog {
		t.Errorf("expected custom log name %q, got %q", customLog, client.lastLogName)
	}
	if client.lastEntry.Severity != "ERROR" {
		t.Errorf("expected severity ERROR, got %q", client.lastEntry.Severity)
	}

	payload := client.lastEntry.Payload.(cloudaudit.CloudAuditLogPayload)
	if payload.ServiceName != customService {
		t.Errorf("expected serviceName %q, got %q", customService, payload.ServiceName)
	}
	if payload.Status["code"] == 0 || payload.Status["message"] != "permission denied" {
		t.Errorf("expected error status, got %+v", payload.Status)
	}
}

func TestCloudAuditLogger_MissingClient(t *testing.T) {
	_, err := cloudaudit.New(cloudaudit.Config{
		ProjectID: "my-project",
	})
	if err == nil {
		t.Errorf("expected error when Client is nil")
	}
}
