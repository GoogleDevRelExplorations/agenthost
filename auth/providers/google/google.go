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

package google

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/auth/providers"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	analyticsdata "google.golang.org/api/analyticsdata/v1alpha"
	"google.golang.org/api/idtoken"
	"google.golang.org/api/sheets/v4"
)

func init() {
	registry.RegisterProvider(registry.Provider{
		Name:     "google",
		Type:     registry.AuthTypeOAuth2,
		Endpoint: google.Endpoint,
		Scopes: []registry.Scope{
			{
				Value:       "openid",
				Name:        "OpenID Connect",
				Description: "Authenticate using OpenID Connect.",
				Default:     true,
			},
			{
				Value:       "https://www.googleapis.com/auth/userinfo.email",
				Name:        "Email Address",
				Description: "Access your primary Google Account email address.",
				Default:     true,
			},
			{
				Value:       sheets.SpreadsheetsScope,
				Name:        "Google Sheets",
				Description: "Read, create, and update your Google Sheets spreadsheets.",
				Default:     true,
			},
			{
				Value:       sheets.DriveReadonlyScope,
				Name:        "Google Drive (Read-only)",
				Description: "Search, list, and read contents/metadata of files in your Google Drive.",
				Default:     true,
			},
			{
				Value:       analyticsdata.AnalyticsReadonlyScope,
				Name:        "Google Analytics (Read-only)",
				Description: "View your Google Analytics reports and tracking configurations.",
				Default:     true,
			},
			{
				Value:       "https://www.googleapis.com/auth/cloud-platform",
				Name:        "Google Cloud Platform",
				Description: "Full management access to your Google Cloud Platform projects.",
				Default:     false,
			},
		},
	})

	providers.RegisterSigninProvider(&GoogleAuth{})
}

// GoogleAuth implements providers.SigninProvider for Google OIDC/OAuth2 authentication.
type GoogleAuth struct{}

func (a *GoogleAuth) Name() string {
	return "google"
}

func (a *GoogleAuth) Endpoint() oauth2.Endpoint {
	return google.Endpoint
}

func (a *GoogleAuth) DefaultScopes() []string {
	return []string{"openid", "email", "profile"}
}

// UserID resolves the user's Google email address from the ID token or access token userinfo.
func (a *GoogleAuth) UserID(ctx context.Context, tok *oauth2.Token) (string, error) {
	if tok == nil {
		return "", errors.New("nil oauth token")
	}

	if idToken, _ := tok.Extra("id_token").(string); idToken != "" {
		payload, err := idtoken.ParsePayload(idToken)
		if err == nil {
			if email, ok := payload.Claims["email"].(string); ok && email != "" {
				return email, nil
			}
		}
	}

	if tok.AccessToken != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
		if err == nil {
			req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var info struct {
						Email string `json:"email"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&info); err == nil && info.Email != "" {
						return info.Email, nil
					}
				}
			}
		}
	}

	return "", errors.New("unable to resolve user email from Google token")
}
