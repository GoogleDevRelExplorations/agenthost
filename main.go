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
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/GoogleDevRelExplorations/agenthost/a2ahost"
	"github.com/GoogleDevRelExplorations/agenthost/agents/calendar"
	"github.com/GoogleDevRelExplorations/agenthost/agents/example"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/delegated"
	authhttp "github.com/GoogleDevRelExplorations/agenthost/auth/http"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/buffer"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"github.com/spf13/viper"
)

var (
	port           = flag.Int("port", 9001, "Port for the HTTP server to listen on.")
	baseURL        = flag.String("baseurl", "", "Base URL for the server (e.g. http://localhost:9001). If empty, defaults to http://localhost:<port>")
	signinProvider = flag.String("signin-provider", "google", "Default OAuth provider for sign-in (e.g. google, github).")
)

func main() {
	flag.Parse()

	// Initialize viper configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Error reading config file: %v", err)
		}
	}
	viper.AutomaticEnv()

	ctx := context.Background()

	// Instantiate the in-memory token store
	tokenStore := auth.NewInMemoryStore()
	// tokenStore, _ := googlesecretmanager.New(context.Background())

	// 1. Create the ADK agents
	exampleAgent, err := example.NewExampleAgent(ctx)
	if err != nil {
		log.Fatalf("Failed to create example agent: %v", err)
	}
	calendarAgent, err := calendar.NewCalendarAgent(ctx)
	if err != nil {
		log.Fatalf("Failed to create calendar agent: %v", err)
	}

	rdraddr := *baseURL
	if rdraddr == "" {
		rdraddr = fmt.Sprintf("http://localhost:%d", *port)
	}

	// 2. Set up HTTP Mux, session store, and Host wrapper
	mux := http.NewServeMux()
	sessionStore := authsession.NewInMemoryStore()
	host := a2ahost.NewHost(mux, rdraddr, tokenStore, sessionStore)

	// Mount agents
	host.RegisterAgent("/", exampleAgent)
	host.RegisterAgent("/agents/calendar", calendarAgent)

	provider := *signinProvider
	if p := viper.GetString("auth.signin_provider"); p != "" {
		provider = p
	}

	// Mount Login (BFF Session) handler
	loginHandler := authsession.NewHandler(sessionStore, tokenStore, rdraddr, provider, host.ListAgents)
	loginHandler.RegisterRoutes(mux)

	// Mount Delegated Scope Authorization handler
	authzHandler := delegated.NewHandler(tokenStore, rdraddr)
	authzHandler.RegisterRoutes(mux)

	// Custom HTTP endpoints
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Wrap mux with AuthMiddleware to extract session cookie, validate OIDC tokens, and inject DelegatedAuthProvider
	handler := authhttp.Middleware(authhttp.Options{
		SessionStore:    sessionStore,
		CredentialStore: tokenStore,
	})(mux)

	// 5. Start HTTP server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to bind to port: %v", err)
	}

	log.Printf("Starting A2A server on %s (signin provider: %s)", rdraddr, provider)
	log.Printf("Health check available at %s/health", rdraddr)

	if err := http.Serve(listener, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
