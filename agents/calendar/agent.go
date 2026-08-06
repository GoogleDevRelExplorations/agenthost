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

package calendar

import (
	"context"
	"fmt"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/agent/llmagent"
	"google.golang.org/adk/model/gemini"
	"google.golang.org/adk/tool"
)

func init() {
	auth.RequestScope("google", registry.Scope{
		Value:       "https://www.googleapis.com/auth/calendar.readonly",
		Name:        "Google Calendar (readonly)",
		Description: "allows read access to your calendars.",
		Default:     true,
	})
}

// NewCalendarAgent creates a new LLM-based agent equipped with the read_calendar tool.
func NewCalendarAgent(ctx context.Context) (agent.Agent, error) {
	calendarTool, err := NewReadCalendarTool()
	if err != nil {
		return nil, fmt.Errorf("failed to create read_calendar tool: %w", err)
	}

	// Instantiate the default Gemini model
	modelName := "gemini-3.5-flash"
	llm, err := gemini.NewModel(ctx, modelName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize model %q: %w", modelName, err)
	}

	return llmagent.New(llmagent.Config{
		Name:        "calendar_agent",
		Description: "An agent that reads the user's Google Calendar and reports scheduled meetings.",
		Instruction: "You are a calendar assistant. Your task is to read the user's Google Calendar and report scheduled meetings for today or the specified date. Use the 'read_calendar' tool to fetch the meetings, and then summarize them clearly for the user. you may also answer questions about the user's identity from your request context.",
		Model:       llm,
		Tools:       []tool.Tool{calendarTool},
	})
}
