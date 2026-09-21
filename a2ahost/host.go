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
	"net/url"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	autha2a "github.com/GoogleDevRelExplorations/agenthost/auth/a2a"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/runner"
	"google.golang.org/adk/v2/server/adka2a/v2"
	"google.golang.org/adk/v2/session"
)

// Host manages the registration, routing, and Agent Card configuration for multiple A2A agents.
type Host struct {
	mux          *http.ServeMux
	baseURL      string
	store        auth.CredentialStore
	sessionStore auth.SessionStore
	cards        []*a2a.AgentCard
}

// NewHost creates a new Host instance wrapping the provided ServeMux.
func NewHost(mux *http.ServeMux, baseURL string, store auth.CredentialStore, sessionStore auth.SessionStore) *Host {
	return &Host{
		mux:          mux,
		baseURL:      baseURL,
		store:        store,
		sessionStore: sessionStore,
	}
}

// BuildAgentCard is a public builder function that derives an a2a.AgentCard from an ADK agent and base address.
func BuildAgentCard(ag agent.Agent, baseAddr string) *a2a.AgentCard {
	return &a2a.AgentCard{
		Name:        ag.Name(),
		Description: ag.Description(),
		SupportedInterfaces: []*a2a.AgentInterface{
			a2a.NewAgentInterface(baseAddr, a2a.TransportProtocolJSONRPC),
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
		},
	}
}

func (h *Host) AttachA2A(pathPrefix string, ag agent.Agent, card *a2a.AgentCard) error {
	agentprefix, err := url.JoinPath("/", pathPrefix)
	if err != nil {
		return fmt.Errorf("failed to assemble agent url: %w", err)
	}
	cardprefix, err := url.JoinPath("/", pathPrefix, a2asrv.WellKnownAgentCardPath)
	if err != nil {
		return fmt.Errorf("failed to assemble card url: %w", err)
	}
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
		a2asrv.WithCallInterceptors(autha2a.NewAuthInterceptor(h.store, h.sessionStore)),
	)

	jsonrpcHandler := a2asrv.NewJSONRPCHandler(requestHandler)

	h.mux.Handle(agentprefix, http.StripPrefix(pathPrefix, jsonrpcHandler))
	h.mux.Handle(cardprefix, a2asrv.NewStaticAgentCardHandler(card))
	return nil
}

// RegisterAgent mounts an ADK agent onto the Mux at the given path prefix and configures its A2A execution handlers.
func (h *Host) RegisterAgent(pathPrefix string, ag agent.Agent) error {
	baseAddr, err := url.JoinPath(h.baseURL, pathPrefix)
	if err != nil {
		return fmt.Errorf("failed to assemble base url: %w", err)
	}
	card := BuildAgentCard(ag, baseAddr)
	return h.AttachA2A(pathPrefix, ag, card)

}

// ListAgents returns a list of all registered Agent Cards.
func (h *Host) ListAgents() []*a2a.AgentCard {
	return h.cards
}
