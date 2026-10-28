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
	_ "embed"
	"html/template"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
)

//go:embed landing.html
var landingHTML string

var landingTmpl = template.Must(template.New("landing").Parse(landingHTML))

type landingData struct {
	BaseURL string
}

// LandingHandler returns an http.HandlerFunc that renders the landing page or redirects to /status if already logged in.
func LandingHandler(sessionStore auth.SessionStore, baseURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If user has active session cookie, redirect to /status dashboard
		if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
			if userID, err := sessionStore.GetUserID(r.Context(), cookie.Value); err == nil && userID != "" {
				http.Redirect(w, r, "/status", http.StatusSeeOther)
				return
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := landingTmpl.Execute(w, landingData{BaseURL: baseURL}); err != nil {
			http.Error(w, "Failed to render landing page", http.StatusInternalServerError)
		}
	}
}
