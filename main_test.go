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
	"testing"
	"time"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/GoogleDevRelExplorations/agenthost/a2ahost"
	"github.com/GoogleDevRelExplorations/agenthost/agents/example"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/delegated"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
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

	mux := http.NewServeMux()
	host := a2ahost.NewHost(mux, addr, tokenStore)
	host.RegisterAgent("/", exampleAgent)

	sessionStore := authsession.NewInMemoryStore()

	loginHandler := authsession.NewHandler(sessionStore, tokenStore, addr, host.ListAgents)
	loginHandler.RegisterRoutes(mux)

	authzHandler := delegated.NewHandler(tokenStore, addr)
	authzHandler.RegisterRoutes(mux)

	// Custom HTTP endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	handler := authsession.Middleware(sessionStore)(mux)
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
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"status":"ok"}` {
		t.Errorf("Expected health body `{\"status\":\"ok\"}`, got %q", string(body))
	}

	// 5. Test Agent Card endpoint
	cardResp, err := http.Get(addr + a2asrv.WellKnownAgentCardPath)
	if err != nil {
		t.Fatalf("Failed to request agent card: %v", err)
	}
	defer cardResp.Body.Close()
	if cardResp.StatusCode != http.StatusOK {
		t.Errorf("Expected agent card status code 200, got %d", cardResp.StatusCode)
	}
	var card a2a.AgentCard
	if err := json.NewDecoder(cardResp.Body).Decode(&card); err != nil {
		t.Fatalf("Failed to parse agent card response: %v", err)
	}
	if card.Name != exampleAgent.Name() {
		t.Errorf("Expected agent card name %q, got %q", exampleAgent.Name(), card.Name)
	}

	// 6. Test Send Message A2A endpoint
	reqBody := a2a.SendMessageRequest{
		Message: a2a.NewMessage(
			a2a.MessageRoleUser,
			a2a.NewTextPart("Test Hello"),
		),
	}
	reqJSON, _ := json.Marshal(reqBody)

	sendResp, err := http.Post(addr+"/message:send", "application/json", bytes.NewReader(reqJSON))
	if err != nil {
		t.Fatalf("Failed to post message: %v", err)
	}
	defer sendResp.Body.Close()

	if sendResp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(sendResp.Body)
		t.Fatalf("Expected status code 200, got %d. Response: %s", sendResp.StatusCode, string(bodyBytes))
	}

	var streamResp a2a.StreamResponse
	if err := json.NewDecoder(sendResp.Body).Decode(&streamResp); err != nil {
		t.Fatalf("Failed to decode send message response: %v", err)
	}

	task, ok := streamResp.Event.(*a2a.Task)
	if !ok {
		t.Fatalf("Expected event to be a Task, got %T", streamResp.Event)
	}

	t.Logf("Task ID: %s, Status: %s", task.ID, task.Status.State)
	for i, msg := range task.History {
		t.Logf("History[%d] Role: %s, Parts count: %d", i, msg.Role, len(msg.Parts))
		for j, p := range msg.Parts {
			t.Logf("  Part[%d] Text: %q", j, p.Text())
		}
	}

	t.Logf("Artifacts count: %d", len(task.Artifacts))
	for i, art := range task.Artifacts {
		t.Logf("Artifact[%d] ID: %s, Name: %s, Parts count: %d", i, art.ID, art.Name, len(art.Parts))
		for j, p := range art.Parts {
			t.Logf("  Part[%d] Text: %q", j, p.Text())
		}
	}

	// Verify that we received at least one artifact containing the agent's response
	if len(task.Artifacts) == 0 {
		t.Fatalf("Expected at least 1 artifact, got 0")
	}

	art := task.Artifacts[0]
	if len(art.Parts) == 0 {
		t.Fatalf("Expected artifact to have parts, got 0")
	}

	part := art.Parts[0]
	expectedPrefix := `Hello! You said: "Test Hello"`
	if !strings.HasPrefix(part.Text(), expectedPrefix) {
		t.Errorf("Expected response text to start with %q, got %q", expectedPrefix, part.Text())
	}
}

func TestBFFAuth(t *testing.T) {
	ctx := context.Background()
	sessionStore := authsession.NewInMemoryStore()

	// Create a dummy handler that returns the Authorization header it received
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"auth_header":%q}`, r.Header.Get("Authorization"))))
	})

	// Wrap with AuthMiddleware
	handler := authsession.Middleware(sessionStore)(dummyHandler)

	// Create test server
	server := httptest.NewServer(handler)
	defer server.Close()

	// Map a dummy session ID to a dummy ID Token
	sessionID := "test-session-123"
	idToken := "test-id-token-abc"
	err := sessionStore.SetIDToken(ctx, sessionID, idToken)
	if err != nil {
		t.Fatalf("Failed to set ID token: %v", err)
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
		AuthHeader string `json:"auth_header"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	expectedHeader := "Bearer " + idToken
	if res.AuthHeader != expectedHeader {
		t.Errorf("Expected Auth Header %q, got %q", expectedHeader, res.AuthHeader)
	}
}

func TestMultiUserCredentialStore(t *testing.T) {
	ctx := context.Background()
	store := auth.NewInMemoryStore()

	email1 := "user1@example.com"
	email2 := "user2@example.com"
	provider := "google"

	token1 := &oauth2.Token{AccessToken: "token-user-1"}
	token2 := &oauth2.Token{AccessToken: "token-user-2"}

	tokBytes1, _ := json.Marshal(token1)
	tokBytes2, _ := json.Marshal(token2)

	// Set tokens
	if err := store.SetCredential(ctx, email1, provider, tokBytes1); err != nil {
		t.Fatalf("Failed to set token for user1: %v", err)
	}
	if err := store.SetCredential(ctx, email2, provider, tokBytes2); err != nil {
		t.Fatalf("Failed to set token for user2: %v", err)
	}

	// Retrieve tokens
	gotBytes1, err := store.GetCredential(ctx, email1, provider)
	if err != nil {
		t.Fatalf("Failed to get token for user1: %v", err)
	}
	var gotToken1 oauth2.Token
	json.Unmarshal(gotBytes1, &gotToken1)
	if gotToken1.AccessToken != "token-user-1" {
		t.Errorf("Expected token-user-1, got %q", gotToken1.AccessToken)
	}

	gotBytes2, err := store.GetCredential(ctx, email2, provider)
	if err != nil {
		t.Fatalf("Failed to get token for user2: %v", err)
	}
	var gotToken2 oauth2.Token
	json.Unmarshal(gotBytes2, &gotToken2)
	if gotToken2.AccessToken != "token-user-2" {
		t.Errorf("Expected token-user-2, got %q", gotToken2.AccessToken)
	}
}

