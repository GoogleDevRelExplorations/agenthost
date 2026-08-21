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

package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"github.com/GoogleDevRelExplorations/agenthost/auth/ui"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

// Handler manages OIDC direct user login, status dashboard, and callback token resolution.
type Handler struct {
	store      Store
	credStore  auth.CredentialStore
	serverAddr string
	listAgents func() []*a2a.AgentCard
}

// NewHandler creates a new Handler.
func NewHandler(store Store, credStore auth.CredentialStore, serverAddr string, listAgents func() []*a2a.AgentCard) *Handler {
	return &Handler{
		store:      store,
		credStore:  credStore,
		serverAddr: serverAddr,
		listAgents: listAgents,
	}
}

// RegisterRoutes mounts OIDC login and status endpoints onto the provided ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", h.HandleLogin)
	mux.HandleFunc("GET /status", h.HandleStatus)
}

// HandleStatus renders the standalone post-login session and provider dashboard.
func (h *Handler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	sessionID := cookie.Value
	idToken, err := h.store.GetIDToken(r.Context(), sessionID)
	if err != nil || idToken == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	email := ""
	if payload, err := idtoken.ParsePayload(idToken); err == nil {
		email, _ = payload.Claims["email"].(string)
	}
	if email == "" {
		email = "testuser@example.com"
	}

	type ProviderStatus struct {
		Name    string
		Type    string
		Enabled bool
	}
	var statuses []ProviderStatus
	for _, p := range registry.ListProviders() {
		_, err := h.credStore.GetCredential(r.Context(), email, p.Name)
		statuses = append(statuses, ProviderStatus{
			Name:    p.Name,
			Type:    p.Type,
			Enabled: err == nil,
		})
	}

	slices.SortFunc(statuses, func(a, b ProviderStatus) int {
		return strings.Compare(a.Name, b.Name)
	})

	var agents []*a2a.AgentCard
	if h.listAgents != nil {
		agents = h.listAgents()
	}

	ui.Render(w, "status.html", map[string]any{
		"PageTitle": "a2a-server // session dashboard",
		"Email":     email,
		"SessionID": sessionID,
		"Providers": statuses,
		"Agents":    agents,
	})
}

// HandleLogin processes direct Google OIDC login and state callbacks.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	providerName := "google"
	provider, ok := registry.GetProvider(providerName)
	if !ok {
		http.Error(w, fmt.Sprintf("Default provider '%s' not registered", providerName), http.StatusInternalServerError)
		return
	}

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
	redirectURL := fmt.Sprintf("%s/login", h.serverAddr)

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     provider.Endpoint,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
	}

	query := r.URL.Query()
	if code := query.Get("code"); code != "" {
		tok, err := config.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusBadRequest)
			return
		}

		idToken, _ := tok.Extra("id_token").(string)
		if idToken == "" {
			http.Error(w, "No ID token returned by provider", http.StatusInternalServerError)
			return
		}

		// Decode email from the ID Token
		email := ""
		payload, err := idtoken.ParsePayload(idToken)
		if err == nil {
			email, _ = payload.Claims["email"].(string)
		}

		// Generate secure session ID
		sessionID := uuid.NewString()

		// Save session mapping to session Store
		if err := h.store.SetIDToken(r.Context(), sessionID, idToken); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			// If serving over http, un-set secure (e.g. for localhost use)
			Secure:   h.serverAddr[0:5] == "http:",
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(time.Until(tok.Expiry).Seconds()),
		})

		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			http.Redirect(w, r, "/status", http.StatusSeeOther)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"email":   email,
			"status":  "logged_in",
			"session": sessionID,
		})
		return
	}

	if errStr := query.Get("error"); errStr != "" {
		http.Error(w, fmt.Sprintf("Authorization error: %s", errStr), http.StatusBadRequest)
		return
	}

	authURL := config.AuthCodeURL(
		"state-token",
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}
