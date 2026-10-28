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

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/GoogleDevRelExplorations/agenthost/auth/credentialstore/googlesecretmanager"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/buffer"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/github"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"github.com/spf13/viper"
)

var (
	port       = flag.Int("port", 9002, "Port for the HTTP MCP server to listen on.")
	baseURL    = flag.String("baseurl", "", "Base URL for the server (e.g. http://localhost:9002). If empty, defaults to http://localhost:<port>")
	configFile = flag.String("config", "", "Path to configuration file (defaults to config.yaml).")
)

func main() {
	flag.Parse()

	// 1. Initialize viper configuration
	if *configFile != "" {
		viper.SetConfigFile(*configFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("../../")
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Printf("Warning reading config file: %v", err)
		}
	}
	viper.AutomaticEnv()

	ctx := context.Background()

	// 2. Initialize credential token store (Google Secret Manager if configured, or In-Memory)
	var tokenStore auth.CredentialStore
	smStore, err := googlesecretmanager.New(ctx)
	if err == nil {
		tokenStore = smStore
		log.Println("Using Google Secret Manager for durable delegated credential storage.")
	} else {
		tokenStore = auth.NewInMemoryStore()
		log.Printf("Google Secret Manager not available (%v); using in-memory credential store.", err)
	}

	// 3. Initialize session store
	sessionStore := authsession.NewInMemoryStore()

	rdraddr := *baseURL
	if rdraddr == "" {
		rdraddr = fmt.Sprintf("http://localhost:%d", *port)
	}

	// 4. Construct server router with login, authorization, and MCP handlers
	handler := SetupRouter(ServerOptions{
		BaseURL:      rdraddr,
		TokenStore:   tokenStore,
		SessionStore: sessionStore,
	})

	// 5. Start HTTP server
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("Failed to bind to port %d: %v", *port, err)
	}

	log.Println("=================================================================")
	log.Printf("🚀 Google Calendar MCP Server running on %s", rdraddr)
	log.Printf("👉 Login URL:                     %s/login", rdraddr)
	log.Printf("👉 Status Dashboard:              %s/status", rdraddr)
	log.Printf("👉 Authorize Google Calendar:     %s/authorize/google", rdraddr)
	log.Printf("👉 MCP Streamable HTTP Endpoint:  %s/mcp", rdraddr)
	log.Printf("👉 MCP SSE Endpoint:              %s/sse", rdraddr)
	log.Printf("👉 Health Check:                  %s/health", rdraddr)
	log.Println("=================================================================")

	if err := http.Serve(listener, handler); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
