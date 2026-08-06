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

package delegated

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/buffer"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

func TestAuthorizeGET(t *testing.T) {
	store := auth.NewInMemoryStore()
	handler := NewHandler(store, "http://localhost:9001")

	t.Run("Google Provider (Default)", func(t *testing.T) {
		viper.Set("oauth.google.client_id", "mock-google-client-id")
		viper.Set("oauth.google.client_secret", "mock-google-client-secret")

		provider := registry.Provider{
			Name:        "google",
			Description: "Custom google description text",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			Scopes: []registry.Scope{
				{Value: "https://www.googleapis.com/auth/calendar.readonly", Description: "Read your calendar events"},
			},
		}
		registry.RegisterProvider(provider)

		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		req := httptest.NewRequest("GET", "/authorize", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Custom google description text") {
			t.Errorf("Expected Description to be rendered, got body:\n%s", body)
		}
		if !strings.Contains(body, "https://www.googleapis.com/auth/calendar.readonly") {
			t.Errorf("Expected calendar scope in body, got:\n%s", body)
		}
	})

	t.Run("GitHub Provider", func(t *testing.T) {
		viper.Set("oauth.github.client_id", "mock-github-client-id")
		viper.Set("oauth.github.client_secret", "mock-github-client-secret")

		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		req := httptest.NewRequest("GET", "/authorize/github", nil)
		w := httptest.NewRecorder()

		mux.ServeHTTP(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status code 200, got %d", resp.StatusCode)
		}

		body := w.Body.String()
		if !strings.Contains(body, "github APIs") {
			t.Errorf("Expected HTML intro text to refer to 'github APIs', got body:\n%s", body)
		}
		if !strings.Contains(body, "read:user") {
			t.Errorf("Expected read:user scope in body, got:\n%s", body)
		}
	})

	t.Run("Buffer Provider (API Key)", func(t *testing.T) {
		mux := http.NewServeMux()
		handler.RegisterRoutes(mux)

		// Test GET /authorize/buffer
		reqGET := httptest.NewRequest("GET", "/authorize/buffer", nil)
		wGET := httptest.NewRecorder()
		mux.ServeHTTP(wGET, reqGET)

		respGET := wGET.Result()
		if respGET.StatusCode != http.StatusOK {
			t.Fatalf("GET /authorize/buffer: Expected status code 200, got %d", respGET.StatusCode)
		}

		bodyGET := wGET.Body.String()
		if !strings.Contains(bodyGET, "For social media tools at http://buffer.com.") {
			t.Errorf("Expected Buffer description in body, got:\n%s", bodyGET)
		}

		// Test POST /authorize/buffer
		form := strings.NewReader("api_key=buf_mockapikey12345")
		reqPOST := httptest.NewRequest("POST", "/authorize/buffer", form)
		reqPOST.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		wPOST := httptest.NewRecorder()
		mux.ServeHTTP(wPOST, reqPOST)

		respPOST := wPOST.Result()
		if respPOST.StatusCode != http.StatusOK {
			t.Fatalf("POST /authorize/buffer: Expected status code 200, got %d", respPOST.StatusCode)
		}

		bodyPOST := wPOST.Body.String()
		if !strings.Contains(bodyPOST, "success") {
			t.Errorf("Expected success alert in body, got:\n%s", bodyPOST)
		}

		// Verify credential was saved in store
		cred, err := store.GetCredential(context.Background(), "testuser@example.com", "buffer")
		if err != nil {
			t.Fatalf("Expected credential to be saved in store, got error: %v", err)
		}
		if string(cred) != "buf_mockapikey12345" {
			t.Errorf("Expected saved API key 'buf_mockapikey12345', got %q", string(cred))
		}
	})
}
