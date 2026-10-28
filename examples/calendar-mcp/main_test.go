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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
	googlecalendar "google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

func setupTestServer(t *testing.T, tokenStore auth.CredentialStore, sessionStore auth.SessionStore) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)

	handler := SetupRouter(ServerOptions{
		BaseURL:      addr,
		TokenStore:   tokenStore,
		SessionStore: sessionStore,
	})

	server := &http.Server{Handler: handler}
	go func() {
		_ = server.Serve(listener)
	}()

	cleanup := func() {
		_ = server.Close()
	}

	time.Sleep(50 * time.Millisecond)
	return addr, cleanup
}

func TestHealthAndLandingPage(t *testing.T) {
	tokenStore := auth.NewInMemoryStore()
	sessionStore := authsession.NewInMemoryStore()
	addr, cleanup := setupTestServer(t, tokenStore, sessionStore)
	defer cleanup()

	// 1. Test Health Endpoint
	resp, err := http.Get(addr + "/health")
	if err != nil {
		t.Fatalf("Failed to call /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for /health, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("Expected status ok in body, got: %s", string(body))
	}

	// 2. Test Landing Page
	respLanding, err := http.Get(addr + "/")
	if err != nil {
		t.Fatalf("Failed to call /: %v", err)
	}
	defer respLanding.Body.Close()

	if respLanding.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for /, got %d", respLanding.StatusCode)
	}
	bodyLanding, _ := io.ReadAll(respLanding.Body)
	if !strings.Contains(string(bodyLanding), "Google Calendar MCP Server") {
		t.Errorf("Expected title in landing page, got: %s", string(bodyLanding))
	}
}

func TestMCPListTools(t *testing.T) {
	ctx := context.Background()
	tokenStore := auth.NewInMemoryStore()
	sessionStore := authsession.NewInMemoryStore()
	addr, cleanup := setupTestServer(t, tokenStore, sessionStore)
	defer cleanup()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             addr + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("Failed to connect to MCP server: %v", err)
	}
	defer session.Close()

	listRes, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	toolNames := make(map[string]bool)
	for _, tool := range listRes.Tools {
		toolNames[tool.Name] = true
	}

	for _, expected := range []string{"read_calendar", "get_user_info"} {
		if !toolNames[expected] {
			t.Errorf("Expected tool %q in ListTools result, got: %v", expected, listRes.Tools)
		}
	}
}

func TestMCPCallTool_Unauthenticated(t *testing.T) {
	ctx := context.Background()
	tokenStore := auth.NewInMemoryStore()
	sessionStore := authsession.NewInMemoryStore()
	addr, cleanup := setupTestServer(t, tokenStore, sessionStore)
	defer cleanup()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             addr + "/mcp",
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("Failed to connect to MCP server: %v", err)
	}
	defer session.Close()

	// 1. get_user_info without authentication should report unauthenticated
	userRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_user_info",
	})
	if err != nil {
		t.Fatalf("CallTool get_user_info failed: %v", err)
	}
	if userRes.IsError {
		t.Errorf("Expected get_user_info to succeed with unauthenticated status, got error: %v", userRes)
	}

	// 2. read_calendar without authentication should return an error
	calRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "read_calendar",
		Arguments: map[string]any{"date": "2026-09-01"},
	})
	if err != nil {
		t.Fatalf("CallTool read_calendar RPC failed: %v", err)
	}
	if !calRes.IsError {
		t.Errorf("Expected read_calendar to return IsError=true when unauthenticated, got: %v", calRes)
	}
}

type headerTransport struct {
	base    http.RoundTripper
	headers map[string]string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	for k, v := range t.headers {
		clone.Header.Set(k, v)
	}
	return t.base.RoundTrip(clone)
}

func TestMCPCallTool_Authenticated(t *testing.T) {
	ctx := context.Background()
	tokenStore := auth.NewInMemoryStore()
	sessionStore := authsession.NewInMemoryStore()

	email := "testuser@example.com"
	sessionID := "sess-abc-123"

	oauthTok := &oauth2.Token{
		AccessToken: "ya29.mock-google-token",
		TokenType:   "Bearer",
	}

	// 1. Setup session and delegated OAuth credentials in stores
	if err := sessionStore.SetSession(ctx, &authsession.SessionData{
		ID:        sessionID,
		UserID:    email,
		Provider:  "google",
		Token:     oauthTok,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Failed to store session: %v", err)
	}

	tokBytes, _ := json.Marshal(oauthTok)
	if err := tokenStore.SetCredential(ctx, email, "google", tokBytes); err != nil {
		t.Fatalf("Failed to store delegated credential: %v", err)
	}

	// 2. Mock Google Calendar API backend
	mockCalendarHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer ya29.mock-google-token" {
			http.Error(w, fmt.Sprintf("Unauthorized: received header %q", authHeader), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/calendars/primary/events") {
			_ = json.NewEncoder(w).Encode(googlecalendar.Events{
				Items: []*googlecalendar.Event{
					{
						Id:      "event-1",
						Summary: "Agent Architecture Sync",
						Start: &googlecalendar.EventDateTime{
							DateTime: "2026-09-01T10:00:00-07:00",
						},
						End: &googlecalendar.EventDateTime{
							DateTime: "2026-09-01T11:00:00-07:00",
						},
						Location: "Google Meet",
						Organizer: &googlecalendar.EventOrganizer{
							Email: email,
							Self:  true,
						},
					},
					{
						Id:      "event-2",
						Summary: "Team Lunch",
						Start: &googlecalendar.EventDateTime{
							DateTime: "2026-09-01T12:00:00-07:00",
						},
						End: &googlecalendar.EventDateTime{
							DateTime: "2026-09-01T13:00:00-07:00",
						},
					},
				},
			})
			return
		}

		http.NotFound(w, r)
	})

	mockCalServer := httptest.NewServer(mockCalendarHandler)
	defer mockCalServer.Close()

	// Override calendarServiceFactory to route to mock server
	oldFactory := calendarServiceFactory
	calendarServiceFactory = func(ctx context.Context) (*googlecalendar.Service, error) {
		client, err := auth.NewClient("google")
		if err != nil {
			return nil, err
		}
		return googlecalendar.NewService(ctx, option.WithHTTPClient(client), option.WithEndpoint(mockCalServer.URL))
	}
	defer func() { calendarServiceFactory = oldFactory }()

	addr, cleanup := setupTestServer(t, tokenStore, sessionStore)
	defer cleanup()

	// 3. Connect MCP client with session ID as Bearer token
	httpClient := &http.Client{
		Transport: &headerTransport{
			base: http.DefaultTransport,
			headers: map[string]string{
				"Authorization": "Bearer " + sessionID,
			},
		},
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "authenticated-client", Version: "1.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             addr + "/mcp",
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("Failed to connect authenticated MCP client: %v", err)
	}
	defer session.Close()

	// 4. Test get_user_info
	userRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_user_info",
	})
	if err != nil {
		t.Fatalf("CallTool get_user_info failed: %v", err)
	}
	if userRes.IsError {
		t.Fatalf("get_user_info returned error: %v", userRes)
	}
	userJSON, _ := json.Marshal(userRes.StructuredContent)
	if !strings.Contains(string(userJSON), email) {
		t.Errorf("Expected email %s in user info output, got: %s", email, string(userJSON))
	}

	// 5. Test read_calendar
	calRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "read_calendar",
		Arguments: map[string]any{
			"date": "2026-09-01",
		},
	})
	if err != nil {
		t.Fatalf("CallTool read_calendar failed: %v", err)
	}
	if calRes.IsError {
		t.Fatalf("read_calendar returned error: %v", calRes)
	}
	calJSON, _ := json.Marshal(calRes.StructuredContent)
	if !strings.Contains(string(calJSON), "Agent Architecture Sync") || !strings.Contains(string(calJSON), "Team Lunch") {
		t.Errorf("Expected events in output, got: %s", string(calJSON))
	}

	// 6. Test invalid date format error handling
	invCalRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "read_calendar",
		Arguments: map[string]any{
			"date": "invalid-date",
		},
	})
	if err != nil {
		t.Fatalf("CallTool read_calendar RPC failed: %v", err)
	}
	if !invCalRes.IsError {
		t.Errorf("Expected IsError=true for invalid date format, got: %v", invCalRes)
	}
}

func TestAuthRoutes(t *testing.T) {
	tokenStore := auth.NewInMemoryStore()
	sessionStore := authsession.NewInMemoryStore()
	addr, cleanup := setupTestServer(t, tokenStore, sessionStore)
	defer cleanup()

	// 1. Test /status redirect without cookie
	req, _ := http.NewRequest("GET", addr+"/status", nil)
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to request /status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Expected redirect 303 for unauthenticated /status, got %d", resp.StatusCode)
	}

	// 2. Test /status with valid session cookie
	sessionID := "test-sess-status"
	_ = sessionStore.SetSession(context.Background(), &authsession.SessionData{
		ID:        sessionID,
		UserID:    "user-tester@example.com",
		Provider:  "google",
		CreatedAt: time.Now(),
	})
	reqWithCookie, _ := http.NewRequest("GET", addr+"/status", nil)
	reqWithCookie.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: sessionID,
	})
	respStatus, err := http.DefaultClient.Do(reqWithCookie)
	if err != nil {
		t.Fatalf("Failed to request /status with cookie: %v", err)
	}
	defer respStatus.Body.Close()
	if respStatus.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for authenticated /status, got %d", respStatus.StatusCode)
	}
	bodyStatus, _ := io.ReadAll(respStatus.Body)
	if !strings.Contains(string(bodyStatus), "google-calendar-mcp") {
		t.Errorf("Expected google-calendar-mcp agent in dashboard, got: %s", string(bodyStatus))
	}
}
