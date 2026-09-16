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
	"bytes"
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

	"github.com/GoogleDevRelExplorations/agenthost/a2ahost"
	"github.com/GoogleDevRelExplorations/agenthost/agents/example"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/delegated"
	authhttp "github.com/GoogleDevRelExplorations/agenthost/auth/http"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"golang.org/x/oauth2"
)

func TestServerA2A(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Setup the ADK agent
	exampleAgent, err := example.NewExampleAgent(ctx)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	tokenStore := auth.NewInMemoryStore()

	// 2. Find a free port and start the HTTP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to bind: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	addr := fmt.Sprintf("http://127.0.0.1:%d", port)

	sessionStore := authsession.NewInMemoryStore()

	mux := http.NewServeMux()
	host := a2ahost.NewHost(mux, addr, tokenStore, sessionStore)
	host.RegisterAgent("/", exampleAgent)

	loginHandler := authsession.NewHandler(sessionStore, tokenStore, addr, "google", host.ListAgents)
	loginHandler.RegisterRoutes(mux)

	authzHandler := delegated.NewHandler(tokenStore, addr)
	authzHandler.RegisterRoutes(mux)

	// Custom HTTP endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	handler := authhttp.Middleware(authhttp.Options{
		SessionStore:    sessionStore,
		CredentialStore: tokenStore,
	})(mux)
	server := &http.Server{Handler: handler}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}
	}()
	defer server.Shutdown(ctx)

	// Wait a moment for server to start
	time.Sleep(100 * time.Millisecond)

	// 4. Test health check custom endpoint
	resp, err := http.Get(addr + "/health")
	if err != nil {
		t.Fatalf("Failed to request health endpoint: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	// 5. Test agent card discovery for root agent
	agentCardURL := addr + "/.well-known/agent-card.json"
	resp, err = http.Get(agentCardURL)
	if err != nil {
		t.Fatalf("Failed to fetch root agent card: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	var card a2a.AgentCard
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		t.Fatalf("Failed to decode agent card: %v", err)
	}

	if card.Name != "example_adk_agent" {
		t.Errorf("Expected agent name 'example_adk_agent', got %q", card.Name)
	}

	// 6. Test A2A Client Message sending
	client, err := a2aclient.NewFromCard(ctx, &card)
	if err != nil {
		t.Fatalf("Failed to create A2A client: %v", err)
	}

	msgReq := &a2a.SendMessageRequest{
		Message: a2a.NewMessage(
			a2a.MessageRoleUser,
			a2a.NewTextPart("Hello agent"),
		),
	}
	msgReq.Message.ContextID = "test-ctx-1"

	msgResp, err := client.SendMessage(ctx, msgReq)
	if err != nil {
		t.Fatalf("Failed to send message via A2A client: %v", err)
	}

	if msgResp == nil {
		t.Fatalf("Expected non-nil message response")
	}

	// Verify text content
	var textFound bool
	switch resp := msgResp.(type) {
	case *a2a.Message:
		for _, p := range resp.Parts {
			if txt := p.Text(); txt != "" {
				textFound = true
				if !strings.Contains(txt, "Hello agent") {
					t.Errorf("Expected response to echo prompt, got %q", txt)
				}
			}
		}
	case *a2a.Task:
		for _, m := range resp.History {
			for _, p := range m.Parts {
				if txt := p.Text(); txt != "" {
					textFound = true
					if !strings.Contains(txt, "Hello agent") {
						t.Errorf("Expected response to echo prompt, got %q", txt)
					}
				}
			}
		}
	default:
		t.Fatalf("Unexpected response type %T", msgResp)
	}
	if !textFound {
		t.Errorf("No text part found in response: %+v", msgResp)
	}

	// 7. Test direct JSON-RPC HTTP POST
	jsonrpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "test-jsonrpc-1",
		"method":  "SendMessage",
		"params": a2a.SendMessageRequest{
			Message: a2a.NewMessage(
				a2a.MessageRoleUser,
				a2a.NewTextPart("Test JSON-RPC Raw"),
			),
		},
	}
	rawReqBytes, _ := json.Marshal(jsonrpcReq)
	httpResp, err := http.Post(addr+"/", "application/json", bytes.NewReader(rawReqBytes))
	if err != nil {
		t.Fatalf("Failed to post JSON-RPC request: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(httpResp.Body)
		t.Fatalf("Expected status code 200, got %d. Response: %s", httpResp.StatusCode, string(bodyBytes))
	}

	var jsonrpcResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   any             `json:"error"`
	}
	if err := json.NewDecoder(httpResp.Body).Decode(&jsonrpcResp); err != nil {
		t.Fatalf("Failed to decode JSON-RPC response: %v", err)
	}
	if jsonrpcResp.JSONRPC != "2.0" {
		t.Errorf("Expected jsonrpc 2.0, got %q", jsonrpcResp.JSONRPC)
	}
	if jsonrpcResp.ID != "test-jsonrpc-1" {
		t.Errorf("Expected id test-jsonrpc-1, got %q", jsonrpcResp.ID)
	}
	if jsonrpcResp.Error != nil {
		t.Errorf("Unexpected JSON-RPC error: %v", jsonrpcResp.Error)
	}
}

func TestBFFAuth(t *testing.T) {
	ctx := context.Background()
	sessionStore := authsession.NewInMemoryStore()
	tokenStore := auth.NewInMemoryStore()

	// Create a dummy handler that returns the authenticated user ID
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID := ""
		if p, ok := auth.DelegatedAuthProviderFrom(r.Context()); ok && p != nil {
			userID = p.UserID()
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"user_id":%q}`, userID)))
	})

	// Wrap with AuthMiddleware
	handler := authhttp.Middleware(authhttp.Options{
		SessionStore:    sessionStore,
		CredentialStore: tokenStore,
	})(dummyHandler)

	// Create test server
	server := httptest.NewServer(handler)
	defer server.Close()

	// Map a dummy session ID to a session
	sessionID := "test-session-123"
	err := sessionStore.SetSession(ctx, &authsession.SessionData{
		ID:       sessionID,
		UserID:   "octocat",
		Provider: "github",
	})
	if err != nil {
		t.Fatalf("Failed to set session: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("GET", server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add session_id cookie
	req.AddCookie(&http.Cookie{
		Name:  "session_id",
		Value: sessionID,
	})

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", resp.StatusCode)
	}

	var res struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if res.UserID != "octocat" {
		t.Errorf("Expected UserID octocat, got %q", res.UserID)
	}
}

func TestMultiUserCredentialStore(t *testing.T) {
	ctx := context.Background()
	store := auth.NewInMemoryStore()

	user1 := "user1@example.com"
	user2 := "octocat"
	provider := "github"

	token1 := &oauth2.Token{AccessToken: "token-user-1"}
	token2 := &oauth2.Token{AccessToken: "token-user-2"}

	tokBytes1, _ := json.Marshal(token1)
	tokBytes2, _ := json.Marshal(token2)

	// Set tokens
	if err := store.SetCredential(ctx, user1, provider, tokBytes1); err != nil {
		t.Fatalf("Failed to set token for user1: %v", err)
	}
	if err := store.SetCredential(ctx, user2, provider, tokBytes2); err != nil {
		t.Fatalf("Failed to set token for user2: %v", err)
	}

	// Retrieve tokens
	gotBytes1, err := store.GetCredential(ctx, user1, provider)
	if err != nil {
		t.Fatalf("Failed to get token for user1: %v", err)
	}
	var gotToken1 oauth2.Token
	json.Unmarshal(gotBytes1, &gotToken1)
	if gotToken1.AccessToken != "token-user-1" {
		t.Errorf("Expected token-user-1, got %q", gotToken1.AccessToken)
	}

	gotBytes2, err := store.GetCredential(ctx, user2, provider)
	if err != nil {
		t.Fatalf("Failed to get token for user2: %v", err)
	}
	var gotToken2 oauth2.Token
	json.Unmarshal(gotBytes2, &gotToken2)
	if gotToken2.AccessToken != "token-user-2" {
		t.Errorf("Expected token-user-2, got %q", gotToken2.AccessToken)
	}
}
