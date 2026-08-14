package registry

import (
	"sync"

	"golang.org/x/oauth2"
)

const (
	AuthTypeOAuth2 = "oauth2"
	AuthTypeAPIKey = "apikey"
)

// Scope represents a configurable OAuth scope with human-readable descriptions.
type Scope struct {
	Value       string `json:"value" yaml:"value"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Default     bool   `json:"default" yaml:"default"`
}

// Provider represents a configurable authentication provider.
type Provider struct {
	Name         string          `json:"name" yaml:"name"`
	Type         string          `json:"type" yaml:"type"` // "oauth2" or "apikey"
	Description  string          `json:"description"`
	ClientID     string          `json:"client_id" yaml:"client_id"`
	ClientSecret string          `json:"client_secret" yaml:"client_secret"`
	Endpoint     oauth2.Endpoint `json:"-" yaml:"-"`
	Scopes       []Scope         `json:"scopes" yaml:"scopes"`
}

var (
	providersMu   sync.RWMutex
	providers     = make(map[string]Provider)
	pendingScopes = make(map[string][]Scope)
)

// RegisterProvider adds a provider configuration to the registry.
func RegisterProvider(p Provider) {
	providersMu.Lock()
	defer providersMu.Unlock()

	if scopes, ok := pendingScopes[p.Name]; ok {
		for _, scope := range scopes {
			alreadyPresent := false
			for _, s := range p.Scopes {
				if s.Value == scope.Value {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				p.Scopes = append(p.Scopes, scope)
			}
		}
	}

	providers[p.Name] = p
}

// GetProvider retrieves a provider configuration by name.
func GetProvider(name string) (Provider, bool) {
	providersMu.RLock()
	defer providersMu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// RequestScope adds a scope to the provider's scope list if not already present.
func RequestScope(provider string, scope Scope) (Provider, error) {
	providersMu.Lock()
	defer providersMu.Unlock()

	scopes := pendingScopes[provider]
	alreadyInPending := false
	for _, s := range scopes {
		if s.Value == scope.Value {
			alreadyInPending = true
			break
		}
	}
	if !alreadyInPending {
		pendingScopes[provider] = append(pendingScopes[provider], scope)
	}

	p, ok := providers[provider]
	if !ok {
		return Provider{}, nil
	}

	for _, s := range p.Scopes {
		if s.Value == scope.Value {
			return p, nil // Scope already present
		}
	}

	p.Scopes = append(p.Scopes, scope)
	providers[provider] = p
	return p, nil
}

// ListProviders returns a list of all registered provider configurations.
func ListProviders() []Provider {
	providersMu.RLock()
	defer providersMu.RUnlock()
	var list []Provider
	for _, p := range providers {
		list = append(list, p)
	}
	return list
}
