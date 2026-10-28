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

package cloudaudit

import (
	"context"
	"fmt"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
)

const (
	// DefaultLogName is the default Google Cloud Audit Log name for data access events.
	DefaultLogName = "cloudaudit.googleapis.com/data_access"
	// DefaultServiceName is the default service name emitted in the audit payload.
	DefaultServiceName = "agenthost.auth"
)

// CloudAuditLogPayload represents the standard Google Cloud Audit Log payload.
type CloudAuditLogPayload struct {
	Type               string         `json:"@type"`
	ServiceName        string         `json:"serviceName"`
	MethodName         string         `json:"methodName"`
	ResourceName       string         `json:"resourceName"`
	AuthenticationInfo map[string]any `json:"authenticationInfo"`
	Request            map[string]any `json:"request"`
	Status             map[string]any `json:"status"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

// Entry is the abstracted entry sent to the Cloud Logging Client.
type Entry struct {
	Timestamp time.Time
	Severity  string
	Payload   any
	Labels    map[string]string
}

// Client abstracts the Google Cloud Logging API client for hermetic testing.
type Client interface {
	Log(ctx context.Context, logName string, entry Entry) error
	Close() error
}

// Config configures the CloudAuditLogger.
type Config struct {
	ProjectID   string
	LogName     string // defaults to "cloudaudit.googleapis.com/data_access"
	ServiceName string // defaults to "agenthost.auth"
	Client      Client
}

// Logger implements audit.Logger for Google Cloud Audit Logging.
type Logger struct {
	cfg    Config
	client Client
}

// New creates a new Google Cloud Audit Logger.
func New(cfg Config) (*Logger, error) {
	if cfg.LogName == "" {
		cfg.LogName = DefaultLogName
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = DefaultServiceName
	}
	if cfg.Client == nil {
		return nil, fmt.Errorf("cloudaudit client must be specified")
	}
	return &Logger{
		cfg:    cfg,
		client: cfg.Client,
	}, nil
}

// LogAudit writes a Google Cloud AuditLog entry.
func (l *Logger) LogAudit(ctx context.Context, entry *audit.Entry) error {
	methodName := entry.Action
	if entry.Tool != "" {
		methodName = fmt.Sprintf("%s.%s", entry.Provider, entry.Tool)
	}

	resourceName := fmt.Sprintf("projects/%s/users/%s/providers/%s", l.cfg.ProjectID, entry.UserID, entry.Provider)

	statusCode := 0
	statusMsg := "OK"
	severity := "INFO"
	if !entry.Success {
		statusCode = 7 // PERMISSION_DENIED / ERROR
		statusMsg = entry.Error
		severity = "ERROR"
	}

	payload := CloudAuditLogPayload{
		Type:         "type.googleapis.com/google.cloud.audit.AuditLog",
		ServiceName:  l.cfg.ServiceName,
		MethodName:   methodName,
		ResourceName: resourceName,
		AuthenticationInfo: map[string]any{
			"principalEmail": entry.UserID,
		},
		Request: map[string]any{
			"agent":      entry.Agent,
			"tool":       entry.Tool,
			"parameters": entry.Parameters,
			"action":     entry.Action,
		},
		Status: map[string]any{
			"code":    statusCode,
			"message": statusMsg,
		},
		Metadata: entry.Metadata,
	}

	return l.client.Log(ctx, l.cfg.LogName, Entry{
		Timestamp: entry.Timestamp,
		Severity:  severity,
		Payload:   payload,
		Labels: map[string]string{
			"provider": entry.Provider,
			"user_id":  entry.UserID,
		},
	})
}

// Close closes the underlying client connection.
func (l *Logger) Close() error {
	if l.client != nil {
		return l.client.Close()
	}
	return nil
}
