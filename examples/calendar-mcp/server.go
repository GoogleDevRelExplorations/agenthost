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

package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/delegated"
	authhttp "github.com/GoogleDevRelExplorations/agenthost/auth/http"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ServerOptions contains configuration for setting up the Calendar MCP server.
type ServerOptions struct {
	BaseURL      string
	TokenStore   auth.CredentialStore
	SessionStore auth.SessionStore
	Audience     string
	Validator    auth.ValidatorFunc
	OIDCProvider string
}

// NewMCPServer creates and configures the Model Context Protocol server with Google Calendar tools.
func NewMCPServer(provider *auth.DelegatedAuthProvider) *mcp.Server {
	// this is per-user, needs to be in request handling flow.
	// provider.RequiresApiKey("buffer")
	// provider.RequiresScopes("google", []auth.Scope) // or just scope values?
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "google-calendar-mcp",
			Version: "1.0.0",
		},
		&mcp.ServerOptions{
			Instructions: "This server provides authenticated access to Google Calendar tools (read_calendar, get_user_info) using delegated OAuth2 credentials.",
		},
	)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_calendar",
		Description: "Retrieves scheduled meetings and events from Google Calendar for a specific date (YYYY-MM-DD) or today.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ReadCalendarArgs) (*mcp.CallToolResult, ReadCalendarResult, error) {
		if provider != nil {
			ctx = auth.WithDelegatedAuthProvider(ctx, provider)
		}
		return readCalendarHandler(ctx, req, args)
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_user_info",
		Description: "Returns the current authenticated user's identity and authorized provider status.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, UserInfoResult, error) {
		if provider != nil {
			ctx = auth.WithDelegatedAuthProvider(ctx, provider)
		}
		return getUserInfoHandler(ctx, req, args)
	})

	return server
}

// SetupRouter constructs the HTTP ServeMux with all web, authentication, and MCP routes.
func SetupRouter(opts ServerOptions) http.Handler {
	mux := http.NewServeMux()

	// 1. Mount OIDC Login and Dashboard handlers
	// TODO: refactor this so that status page listings come from a2ahost's registered state, not from the auth handler.
	loginHandler := authsession.NewHandler(opts.SessionStore, opts.TokenStore, opts.BaseURL, opts.OIDCProvider, func() []*a2a.AgentCard {
		return []*a2a.AgentCard{
			{
				Name:        "google-calendar-mcp",
				Description: "Authenticated Model Context Protocol (MCP) server providing Google Calendar tools (read_calendar, get_user_info).",
				SupportedInterfaces: []*a2a.AgentInterface{
					a2a.NewAgentInterface(fmt.Sprintf("%s/mcp", opts.BaseURL), "mcp/streamable-http"),
					a2a.NewAgentInterface(fmt.Sprintf("%s/sse", opts.BaseURL), "mcp/sse"),
				},
				DefaultInputModes:  []string{"application/json"},
				DefaultOutputModes: []string{"application/json"},
			},
		}
	})
	loginHandler.RegisterRoutes(mux)

	// 2. Mount Delegated OAuth Scope Authorization handler
	authzHandler := delegated.NewHandler(opts.TokenStore, opts.BaseURL)
	authzHandler.RegisterRoutes(mux)

	// 3. Mount Streamable HTTP MCP handler (modern MCP transport)
	streamableHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		provider, _ := auth.DelegatedAuthProviderFrom(r.Context())
		return NewMCPServer(provider)
	}, &mcp.StreamableHTTPOptions{})
	mux.Handle("/mcp", streamableHandler)
	mux.Handle("/mcp/", streamableHandler)

	// 4. Mount SSE MCP handler (standard SSE transport)
	sseHandler := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
		provider, _ := auth.DelegatedAuthProviderFrom(r.Context())
		return NewMCPServer(provider)
	}, &mcp.SSEOptions{})
	mux.Handle("/sse", sseHandler)
	mux.Handle("/sse/", sseHandler)

	// 5. Custom Health Check endpoint
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"calendar-mcp"}`))
	})

	// 6. Root Landing Page
	mux.HandleFunc("GET /{$}", LandingHandler(opts.SessionStore, opts.BaseURL))

	// Wrap mux directly with the authhttp.Middleware:
	return authhttp.Middleware(authhttp.Options{
		SessionStore:    opts.SessionStore,
		CredentialStore: opts.TokenStore,
		Audience:        opts.Audience,
		Validator:       opts.Validator,
	})(mux)
}
