// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License58:13 under the License.

package session

import (
	"net/http"
	"strings"
)

// Middleware intercepts requests, extracts the session_id cookie, looks up
// the OIDC ID token, and injects it as an Authorization Bearer header.
func Middleware(store Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			authHeader := r.Header.Get("Authorization")
			// First, check for our custom "session" authorization scheme.
			if strings.Contains(authHeader, "session ") {
				hdrparts := strings.SplitAfterN(authHeader, "session ", 2)
				idToken, err := store.GetIDToken(ctx, hdrparts[1])
				if err == nil && idToken != "" {
					authHeader = "Bearer " + idToken
					r.Header.Set("Authorization", authHeader)
				}
			}
			if authHeader == "" {
				if cookie, err := r.Cookie("session_id"); err == nil {
					idToken, err := store.GetIDToken(ctx, cookie.Value)
					if err == nil && idToken != "" {
						authHeader = "Bearer " + idToken
						r.Header.Set("Authorization", authHeader)
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
