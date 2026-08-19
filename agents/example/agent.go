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

package example

import (
	"context"
	"fmt"
	"iter"
	"log"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/model"
	"google.golang.org/adk/session"
	"google.golang.org/genai"
)

// NewExampleAgent returns a detailed ADK agent that dumps invocation and call context information.
func NewExampleAgent(ctx context.Context) (agent.Agent, error) {
	return agent.New(agent.Config{
		Name:        "example_adk_agent",
		Description: "A debug agent that outputs complete invocation and call context details.",
		Run: func(ctx agent.InvocationContext) iter.Seq2[*session.Event, error] {
			return func(yield func(*session.Event, error) bool) {
				userInput := ""
				if ctx.UserContent() != nil && len(ctx.UserContent().Parts) > 0 {
					userInput = ctx.UserContent().Parts[0].Text
				}

				log.Printf("Agent received input: %q", userInput)

				var sb strings.Builder
				sb.WriteString(fmt.Sprintf("Hello! You said: %q\n\n", userInput))
				sb.WriteString("=== ADK Invocation & Session Information ===\n")
				sb.WriteString(fmt.Sprintf("  - Invocation ID: %s\n", ctx.InvocationID()))
				if ctx.Session() != nil {
					sb.WriteString(fmt.Sprintf("  - Session ID: %s\n", ctx.Session().ID()))
					sb.WriteString(fmt.Sprintf("  - Session App Name: %s\n", ctx.Session().AppName()))
					sb.WriteString(fmt.Sprintf("  - Session User ID: %s\n", ctx.Session().UserID()))
				} else {
					sb.WriteString("  - Session Details: None\n")
				}

				sb.WriteString("\n=== A2A Call Context Information ===\n")
				if callCtx, ok := a2asrv.CallContextFrom(ctx); ok && callCtx != nil {
					sb.WriteString(fmt.Sprintf("  - A2A Method: %s\n", callCtx.Method()))
					sb.WriteString(fmt.Sprintf("  - A2A Tenant: %s\n", callCtx.Tenant()))
					if callCtx.User != nil {
						sb.WriteString(fmt.Sprintf("  - A2A User Name: %s\n", callCtx.User.Name))
						sb.WriteString(fmt.Sprintf("  - A2A User Authenticated: %t\n", callCtx.User.Authenticated))
						sb.WriteString(fmt.Sprintf("  - A2A User Attributes: %v\n", callCtx.User.Attributes))
					} else {
						sb.WriteString("  - A2A User Details: None\n")
					}
					if callCtx.ServiceParams() != nil {
						sb.WriteString("  - A2A Service Parameters:\n")
						for k, v := range callCtx.ServiceParams().List() {
							if strings.ToLower(k) == "authorization" {
								sb.WriteString(fmt.Sprintf("      * %s: %v\n", k, "REDACTED"))
								continue
							}
							sb.WriteString(fmt.Sprintf("      * %s: %v\n", k, v))
						}
					}
				} else {
					sb.WriteString("  - A2A Call Context: Not present in context\n")
				}

				sb.WriteString("\n=== Delegated Authentication Information ===\n")
				if provider, ok := auth.DelegatedAuthProviderFrom(ctx); ok && provider != nil {
					sb.WriteString(fmt.Sprintf("  - Available Providers: [%s]\n", strings.Join(provider.Providers(), ", ")))
				} else {
					sb.WriteString("  - Delegated Auth Provider: None in context\n")
				}

				// Yield the response event
				event := &session.Event{
					LLMResponse: model.LLMResponse{
						Content: &genai.Content{
							Parts: []*genai.Part{
								{
									Text: sb.String(),
								},
							},
						},
					},
				}
				yield(event, nil)
			}
		},
	})
}
