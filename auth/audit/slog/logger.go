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

package slogaudit

import (
	"context"
	"log/slog"

	"github.com/GoogleDevRelExplorations/agenthost/auth/audit"
)

// Option configures the slog audit logger.
type Option func(*Logger)

// WithLevel overrides the default logging level for successful operations.
func WithLevel(level slog.Level) Option {
	return func(l *Logger) {
		l.level = level
	}
}

// Logger implements audit.Logger using log/slog.
type Logger struct {
	logger *slog.Logger
	level  slog.Level
}

// New creates a new slog-backed audit.Logger.
func New(logger *slog.Logger, opts ...Option) *Logger {
	if logger == nil {
		logger = slog.Default()
	}
	l := &Logger{
		logger: logger,
		level:  slog.LevelInfo,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// LogAudit outputs the Entry as structured slog attributes.
func (l *Logger) LogAudit(ctx context.Context, entry *audit.Entry) error {
	level := l.level
	if !entry.Success {
		level = slog.LevelError
	}

	attrs := []slog.Attr{
		slog.String("event", "audit.delegated_token_usage"),
		slog.Time("timestamp", entry.Timestamp),
		slog.String("user_id", entry.UserID),
		slog.String("provider", entry.Provider),
		slog.String("action", entry.Action),
		slog.Bool("success", entry.Success),
	}
	if entry.Agent != "" {
		attrs = append(attrs, slog.String("agent", entry.Agent))
	}
	if entry.Tool != "" {
		attrs = append(attrs, slog.String("tool", entry.Tool))
	}
	if entry.Parameters != nil {
		attrs = append(attrs, slog.Any("parameters", entry.Parameters))
	}
	if entry.Error != "" {
		attrs = append(attrs, slog.String("error", entry.Error))
	}
	if len(entry.Metadata) > 0 {
		attrs = append(attrs, slog.Any("metadata", entry.Metadata))
	}

	l.logger.LogAttrs(ctx, level, "delegated auth token accessed", attrs...)
	return nil
}
