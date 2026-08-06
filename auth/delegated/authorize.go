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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"github.com/GoogleDevRelExplorations/agenthost/auth/ui"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func getUserEmail(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		idToken := strings.TrimPrefix(authHeader, "Bearer ")
		if payload, err := idtoken.ParsePayload(idToken); err == nil {
			if email, ok := payload.Claims["email"].(string); ok && email != "" {
				return email
			}
		}
	}
	return "testuser@example.com"
}

// Handler manages the delegated OAuth2 authorization endpoints.
type Handler struct {
	store      auth.CredentialStore
	serverAddr string
}

// NewHandler creates a new Handler.
func NewHandler(store auth.CredentialStore, serverAddr string) *Handler {
	return &Handler{
		store:      store,
		serverAddr: serverAddr,
	}
}

// RegisterRoutes registers the GET and POST /authorize endpoints.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /authorize", h.HandleAuthorizeGET)
	mux.HandleFunc("GET /authorize/{provider}", h.HandleAuthorizeGET)
	mux.HandleFunc("POST /authorize", h.HandleAuthorizePOST)
	mux.HandleFunc("POST /authorize/{provider}", h.HandleAuthorizePOST)
}

func (h *Handler) HandleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		providerName = r.URL.Query().Get("provider")
	}
	if providerName == "" {
		providerName = "google"
	}
	provider, ok := registry.GetProvider(providerName)
	if !ok {
		http.Error(w, fmt.Sprintf("Provider '%s' not registered", providerName), http.StatusInternalServerError)
		return
	}

	if provider.Type == registry.AuthTypeAPIKey {
		ui.Render(w, "apikey.html", map[string]any{
			"PageTitle":           "a2a-server // api key configuration",
			"ProviderName":        providerName,
			"ProviderDescription": provider.Description,
		})
		return
	}

	if provider.Type != registry.AuthTypeOAuth2 && provider.Type != "" {
		http.Error(w, fmt.Sprintf("Provider '%s' does not support OAuth2 authorization flows", providerName), http.StatusBadRequest)
		return
	}

	redirectURL := fmt.Sprintf("%s/authorize/%s", h.serverAddr, providerName)

	clientIDKey := fmt.Sprintf("oauth.%s.client_id", providerName)
	clientSecretKey := fmt.Sprintf("oauth.%s.client_secret", providerName)
	clientID := viper.GetString(clientIDKey)
	clientSecret := viper.GetString(clientSecretKey)

	if clientID == "" {
		clientID = viper.GetString("oauth.client_id")
	}
	if clientSecret == "" {
		clientSecret = viper.GetString("oauth.client_secret")
	}

	if clientID == "" || clientSecret == "" {
		ui.Render(w, "error.html", map[string]any{
			"PageTitle":    "a2a-server // configuration error",
			"ErrorMessage": fmt.Sprintf("OAuth credentials for '%s' are not configured. Please set them in your config under 'oauth.%s.client_id' and 'oauth.%s.client_secret'.", providerName, providerName, providerName),
			"Scopes":       provider.Scopes,
			"ProviderName": providerName,
		})
		return
	}

	provider.ClientID = clientID
	provider.ClientSecret = clientSecret

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     provider.Endpoint,
		RedirectURL:  redirectURL,
	}

	query := r.URL.Query()
	if code := query.Get("code"); code != "" {
		var scopes []string
		for _, s := range provider.Scopes {
			scopes = append(scopes, s.Value)
		}
		config.Scopes = scopes

		tok, err := config.Exchange(r.Context(), code)
		if err != nil {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // exchange error",
				"ErrorMessage": fmt.Sprintf("Failed to exchange code for token: %v", err),
				"Scopes":       provider.Scopes,
				"ProviderName": providerName,
			})
			return
		}

		idToken, _ := tok.Extra("id_token").(string)
		email := ""
		if idToken != "" {
			payload, err := idtoken.ParsePayload(idToken)
			if err == nil {
				email, _ = payload.Claims["email"].(string)
			}
		}

		if email == "" {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // id token error",
				"ErrorMessage": "Failed to retrieve user email from ID token. Please ensure 'openid' and 'email' scopes are authorized.",
				"Scopes":       provider.Scopes,
				"ProviderName": providerName,
			})
			return
		}

		credBytes, err := json.Marshal(tok)
		if err != nil {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // encoding error",
				"ErrorMessage": fmt.Sprintf("Failed to encode token: %v", err),
				"Scopes":       provider.Scopes,
				"ProviderName": providerName,
			})
			return
		}

		if err := h.store.SetCredential(r.Context(), email, providerName, credBytes); err != nil {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // storage error",
				"ErrorMessage": fmt.Sprintf("Failed to save credentials: %v", err),
				"Scopes":       provider.Scopes,
				"ProviderName": providerName,
			})
			return
		}

		ui.Render(w, "success.html", map[string]any{
			"PageTitle":    "a2a-server // authorization success",
			"Scopes":       provider.Scopes,
			"ProviderName": providerName,
		})
		return
	}

	if errStr := query.Get("error"); errStr != "" {
		ui.Render(w, "error.html", map[string]any{
			"PageTitle":    "a2a-server // provider error",
			"ErrorMessage": fmt.Sprintf("Authorization error from OAuth provider: %s", errStr),
			"Scopes":       provider.Scopes,
			"ProviderName": providerName,
		})
		return
	}

	// Serve the scope selection form dynamically
	ui.Render(w, "oauth2.html", map[string]any{
		"PageTitle":           "a2a-server // scope authorization",
		"Scopes":              provider.Scopes,
		"ProviderName":        providerName,
		"ProviderDescription": provider.Description,
	})
}

func (h *Handler) HandleAuthorizePOST(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	if providerName == "" {
		providerName = r.URL.Query().Get("provider")
	}
	if providerName == "" {
		providerName = "google"
	}
	provider, ok := registry.GetProvider(providerName)
	if !ok {
		http.Error(w, fmt.Sprintf("Provider '%s' not registered", providerName), http.StatusInternalServerError)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	if provider.Type == registry.AuthTypeAPIKey {
		apiKey := r.FormValue("api_key")
		if apiKey == "" {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // validation error",
				"ErrorMessage": "API key cannot be empty.",
				"ProviderName": providerName,
			})
			return
		}

		email := getUserEmail(r)
		if err := h.store.SetCredential(r.Context(), email, providerName, []byte(apiKey)); err != nil {
			ui.Render(w, "error.html", map[string]any{
				"PageTitle":    "a2a-server // storage error",
				"ErrorMessage": fmt.Sprintf("Failed to save API key: %v", err),
				"ProviderName": providerName,
			})
			return
		}

		ui.Render(w, "success.html", map[string]any{
			"PageTitle":    "a2a-server // authorization success",
			"ProviderName": providerName,
		})
		return
	}

	if provider.Type != registry.AuthTypeOAuth2 && provider.Type != "" {
		http.Error(w, fmt.Sprintf("Provider '%s' does not support OAuth2 authorization flows", providerName), http.StatusBadRequest)
		return
	}

	redirectURL := fmt.Sprintf("%s/authorize/%s", h.serverAddr, providerName)

	clientIDKey := fmt.Sprintf("oauth.%s.client_id", providerName)
	clientSecretKey := fmt.Sprintf("oauth.%s.client_secret", providerName)
	clientID := viper.GetString(clientIDKey)
	clientSecret := viper.GetString(clientSecretKey)

	if clientID == "" {
		clientID = viper.GetString("oauth.client_id")
	}
	if clientSecret == "" {
		clientSecret = viper.GetString("oauth.client_secret")
	}

	if clientID == "" || clientSecret == "" {
		http.Error(w, "OAuth credentials not configured", http.StatusInternalServerError)
		return
	}

	provider.ClientID = clientID
	provider.ClientSecret = clientSecret

	// Form already parsed above

	scopes := r.PostForm["scopes"]
	if len(scopes) == 0 {
		ui.Render(w, "error.html", map[string]any{
			"PageTitle":    "a2a-server // validation error",
			"ErrorMessage": "Please select at least one scope to authorize.",
			"Scopes":       provider.Scopes,
			"ProviderName": providerName,
		})
		return
	}

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     provider.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	authURL := config.AuthCodeURL(
		"state-token",
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)

	http.Redirect(w, r, authURL, http.StatusSeeOther)
}
