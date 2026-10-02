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

package audit

import (
	"context"
	"sync"
	"time"
)

// Entry represents an audit record for delegated auth token access or usage.
type Entry struct {
	Timestamp  time.Time      `json:"timestamp"`
	UserID     string         `json:"user_id"`
	Provider   string         `json:"provider"`
	Agent      string         `json:"agent,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Parameters any            `json:"parameters,omitempty"`
	Action     string         `json:"action"` // e.g. "token.access", "token.use"
	Success    bool           `json:"success"`
	Error      string         `json:"error,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Logger defines the interface for an audit logging backend.
type Logger interface {
	LogAudit(ctx context.Context, entry *Entry) error
}

// LoggerFunc allows using a standalone function as a Logger.
type LoggerFunc func(ctx context.Context, entry *Entry) error

// LogAudit calls the underlying function.
func (f LoggerFunc) LogAudit(ctx context.Context, entry *Entry) error {
	return f(ctx, entry)
}

// MultiLogger fans out audit records to multiple loggers.
type MultiLogger []Logger

// LogAudit forwards entry to each logger in MultiLogger, returning the first non-nil error encountered.
func (m MultiLogger) LogAudit(ctx context.Context, entry *Entry) error {
	var firstErr error
	for _, l := range m {
		if l != nil {
			if err := l.LogAudit(ctx, entry); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Context holds contextual invocation metadata (agent, tool, parameters).
type Context struct {
	Agent      string         `json:"agent,omitempty"`
	Tool       string         `json:"tool,omitempty"`
	Parameters any            `json:"parameters,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// Merge combines this Context with another, giving precedence to non-empty fields in other.
func (c Context) Merge(other Context) Context {
	res := c
	if other.Agent != "" {
		res.Agent = other.Agent
	}
	if other.Tool != "" {
		res.Tool = other.Tool
	}
	if other.Parameters != nil {
		res.Parameters = other.Parameters
	}
	if len(other.Metadata) > 0 {
		if res.Metadata == nil {
			res.Metadata = make(map[string]any)
		}
		for k, v := range other.Metadata {
			res.Metadata[k] = v
		}
	}
	return res
}

var (
	defaultLoggerMu sync.RWMutex
	defaultLogger   Logger
)

// SetDefaultLogger sets the package-level default Logger.
func SetDefaultLogger(l Logger) {
	defaultLoggerMu.Lock()
	defer defaultLoggerMu.Unlock()
	defaultLogger = l
}

// DefaultLogger returns the package-level default Logger.
func DefaultLogger() Logger {
	defaultLoggerMu.RLock()
	defer defaultLoggerMu.RUnlock()
	return defaultLogger
}
