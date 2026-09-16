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
	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"github.com/GoogleDevRelExplorations/agenthost/auth/ui"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

// Handler manages direct user login, status dashboard, and callback token resolution.
type Handler struct {
	store          SessionStore
	credStore      auth.CredentialStore
	serverAddr     string
	signinProvider string
	listAgents     func() []*a2a.AgentCard
}

// NewHandler creates a new Handler.
func NewHandler(store SessionStore, credStore auth.CredentialStore, serverAddr string, signinProvider string, listAgents func() []*a2a.AgentCard) *Handler {
	if signinProvider == "" {
		signinProvider = "google"
	}
	return &Handler{
		store:          store,
		credStore:      credStore,
		serverAddr:     serverAddr,
		signinProvider: signinProvider,
		listAgents:     listAgents,
	}
}

// RegisterRoutes mounts login and status endpoints onto the provided ServeMux.
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
	sess, err := h.store.GetSession(r.Context(), sessionID)
	if err != nil || sess == nil || sess.UserID == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	type ProviderStatus struct {
		Name    string
		Type    string
		Enabled bool
	}
	var statuses []ProviderStatus
	for _, p := range registry.ListProviders() {
		var hasCred bool
		if h.credStore != nil {
			_, err := h.credStore.GetCredential(r.Context(), sess.UserID, p.Name)
			hasCred = (err == nil)
		}
		statuses = append(statuses, ProviderStatus{
			Name:    p.Name,
			Type:    p.Type,
			Enabled: hasCred,
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
		"UserID":    sess.UserID,
		"Email":     sess.UserID,
		"SessionID": sessionID,
		"Provider":  sess.Provider,
		"Providers": statuses,
		"Agents":    agents,
	})
}

// HandleLogin processes direct user login and OAuth state callbacks.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	providerName := h.signinProvider
	signinProv, ok := providers.GetSigninProvider(providerName)
	if !ok {
		http.Error(w, fmt.Sprintf("Signin provider '%s' not registered", providerName), http.StatusInternalServerError)
		return
	}

	regProv, _ := registry.GetProvider(providerName)

	clientIDKey := fmt.Sprintf("oauth.%s.client_id", providerName)
	clientSecretKey := fmt.Sprintf("oauth.%s.client_secret", providerName)
	clientID := viper.GetString(clientIDKey)
	clientSecret := viper.GetString(clientSecretKey)

	if clientID == "" {
		clientID = regProv.ClientID
	}
	if clientSecret == "" {
		clientSecret = regProv.ClientSecret
	}

	if clientID == "" || clientSecret == "" {
		http.Error(w, fmt.Sprintf("OAuth credentials not configured for '%s'", providerName), http.StatusInternalServerError)
		return
	}

	redirectURL := fmt.Sprintf("%s/login", h.serverAddr)
	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     signinProv.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       signinProv.DefaultScopes(),
	}

	query := r.URL.Query()
	if code := query.Get("code"); code != "" {
		tok, err := config.Exchange(r.Context(), code)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to exchange code: %v", err), http.StatusBadRequest)
			return
		}

		userID, err := signinProv.UserID(r.Context(), tok)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to resolve user ID: %v", err), http.StatusBadRequest)
			return
		}

		// Generate secure session ID
		sessionID := uuid.NewString()

		// Save session mapping to session Store
		sess := &SessionData{
			ID:        sessionID,
			UserID:    userID,
			Provider:  providerName,
			Token:     tok,
			CreatedAt: time.Now(),
			ExpiresAt: tok.Expiry,
		}
		if err := h.store.SetSession(r.Context(), sess); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
			return
		}

		// Persist delegated credential in CredentialStore
		if h.credStore != nil {
			tokBytes, err := json.Marshal(tok)
			if err == nil {
				_ = h.credStore.SetCredential(r.Context(), userID, providerName, tokBytes)
			}
		}

		maxAge := 86400 * 30 // default 30 days
		if !tok.Expiry.IsZero() {
			diff := int(time.Until(tok.Expiry).Seconds())
			if diff > 0 {
				maxAge = diff
			}
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_id",
			Value:    sessionID,
			Path:     "/",
			HttpOnly: true,
			Secure:   strings.HasPrefix(h.serverAddr, "https:"),
			SameSite: http.SameSiteLaxMode,
			MaxAge:   maxAge,
		})

		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			http.Redirect(w, r, "/status", http.StatusSeeOther)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"user_id": userID,
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
