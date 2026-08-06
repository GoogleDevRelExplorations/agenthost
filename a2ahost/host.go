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

package a2ahost

import (
	"fmt"
	"net/http"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/GoogleDevRelExplorations/agenthost/auth"
	authsession "github.com/GoogleDevRelExplorations/agenthost/auth/session"
	"google.golang.org/adk/agent"
	"google.golang.org/adk/runner"
	"google.golang.org/adk/server/adka2a/v2"
	"google.golang.org/adk/session"
)

// Host manages the registration, routing, and Agent Card configuration for multiple A2A agents.
type Host struct {
	mux     *http.ServeMux
	baseURL string
	store   auth.CredentialStore
	cards   []*a2a.AgentCard
}

// NewHost creates a new Host instance wrapping the provided ServeMux.
func NewHost(mux *http.ServeMux, baseURL string, store auth.CredentialStore) *Host {
	return &Host{
		mux:     mux,
		baseURL: baseURL,
		store:   store,
	}
}

// BuildAgentCard is a public builder function that derives an a2a.AgentCard from an ADK agent and base address.
func BuildAgentCard(ag agent.Agent, baseAddr string) *a2a.AgentCard {
	return &a2a.AgentCard{
		Name:        ag.Name(),
		Description: ag.Description(),
		SupportedInterfaces: []*a2a.AgentInterface{
			a2a.NewAgentInterface(baseAddr, a2a.TransportProtocolHTTPJSON),
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Capabilities:       a2a.AgentCapabilities{Streaming: true},
		Skills:             adka2a.BuildAgentSkills(ag),
		SecurityRequirements: a2a.SecurityRequirementsOptions{
			a2a.SecurityRequirements{
				a2a.SecuritySchemeName("google_oidc"): a2a.SecuritySchemeScopes{"openid"},
			},
		},
		SecuritySchemes: a2a.NamedSecuritySchemes{
			a2a.SecuritySchemeName("google_oidc"): a2a.OpenIDConnectSecurityScheme{
				OpenIDConnectURL: "https://accounts.google.com/.well-known/openid-configuration",
				Description:      "Google OpenID Connect identity provider.",
			},
			a2a.SecuritySchemeName("session"): a2a.HTTPAuthSecurityScheme{
				Scheme:      "session",
				Description: "Session ID issued after logging in to this host",
			},
		},
	}
}

// RegisterAgent mounts an ADK agent onto the Mux at the given path prefix and configures its A2A execution handlers.
func (h *Host) RegisterAgent(pathPrefix string, ag agent.Agent) {
	baseAddr := fmt.Sprintf("%s%s", h.baseURL, pathPrefix)
	if pathPrefix == "/" || pathPrefix == "" {
		baseAddr = h.baseURL
	}
	card := BuildAgentCard(ag, baseAddr)
	h.cards = append(h.cards, card)

	executor := adka2a.NewExecutor(adka2a.ExecutorConfig{
		RunnerConfig: runner.Config{
			AppName:        ag.Name(),
			Agent:          ag,
			SessionService: session.InMemoryService(),
		},
	})

	requestHandler := a2asrv.NewHandler(
		executor,
		a2asrv.WithCallInterceptors(authsession.NewAuthInterceptor(h.store)),
	)

	restHandler := a2asrv.NewRESTHandler(requestHandler)

	if pathPrefix == "/" || pathPrefix == "" {
		h.mux.Handle("/", restHandler)
		h.mux.Handle(a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
		return
	}

	h.mux.Handle(pathPrefix+"/", http.StripPrefix(pathPrefix, restHandler))
	h.mux.Handle(pathPrefix+a2asrv.WellKnownAgentCardPath, a2asrv.NewStaticAgentCardHandler(card))
}

// ListAgents returns a list of all registered Agent Cards.
func (h *Host) ListAgents() []*a2a.AgentCard {
	return h.cards
}
