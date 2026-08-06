package registry

import (
	"testing"
)

func resetRegistry() {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers = make(map[string]Provider)
	pendingScopes = make(map[string][]Scope)
}

func TestRequestScopeAfterRegister(t *testing.T) {
	resetRegistry()

	initialScope := Scope{
		Value:       "openid",
		Name:        "OpenID",
		Description: "OpenID connect scope",
		Default:     true,
	}

	RegisterProvider(Provider{
		Name:   "test-provider",
		Type:   AuthTypeOAuth2,
		Scopes: []Scope{initialScope},
	})

	newScope := Scope{
		Value:       "https://www.googleapis.com/auth/calendar.readonly",
		Name:        "Google Calendar (readonly)",
		Description: "allows read access to your calendars.",
		Default:     true,
	}

	resProvider, err := RequestScope("test-provider", newScope)
	if err != nil {
		t.Fatalf("unexpected error from RequestScope: %v", err)
	}

	if len(resProvider.Scopes) != 2 {
		t.Fatalf("expected 2 scopes in returned provider, got %d", len(resProvider.Scopes))
	}

	p, ok := GetProvider("test-provider")
	if !ok {
		t.Fatalf("expected provider test-provider to be found")
	}

	if len(p.Scopes) != 2 {
		t.Fatalf("expected 2 scopes in registered provider, got %d", len(p.Scopes))
	}

	found := false
	for _, s := range p.Scopes {
		if s.Value == newScope.Value {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected requested scope %q to be present in provider scopes", newScope.Value)
	}
}

func TestRequestScopeBeforeRegister(t *testing.T) {
	resetRegistry()

	calendarScope := Scope{
		Value:       "https://www.googleapis.com/auth/calendar.readonly",
		Name:        "Google Calendar (readonly)",
		Description: "allows read access to your calendars.",
		Default:     true,
	}

	// Request scope before provider is registered (e.g. in agent package init())
	_, err := RequestScope("google", calendarScope)
	if err != nil {
		t.Fatalf("unexpected error from RequestScope before registration: %v", err)
	}

	// Provider is not registered yet
	if _, ok := GetProvider("google"); ok {
		t.Fatalf("expected provider 'google' to not be registered yet")
	}

	// Now register provider (e.g. in provider package init())
	initialScope := Scope{
		Value:       "openid",
		Name:        "OpenID Connect",
		Description: "Authenticate using OpenID Connect.",
		Default:     true,
	}

	RegisterProvider(Provider{
		Name:   "google",
		Type:   AuthTypeOAuth2,
		Scopes: []Scope{initialScope},
	})

	p, ok := GetProvider("google")
	if !ok {
		t.Fatalf("expected provider 'google' to be registered")
	}

	if len(p.Scopes) != 2 {
		t.Fatalf("expected 2 scopes for provider 'google', got %d", len(p.Scopes))
	}

	found := false
	for _, s := range p.Scopes {
		if s.Value == calendarScope.Value {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected scope %q to be merged into provider upon registration", calendarScope.Value)
	}
}

func TestRequestScopeDuplicate(t *testing.T) {
	resetRegistry()

	scope := Scope{
		Value:       "https://www.googleapis.com/auth/calendar.readonly",
		Name:        "Google Calendar (readonly)",
		Description: "allows read access to your calendars.",
		Default:     true,
	}

	// Request scope twice before registration
	RequestScope("google", scope)
	RequestScope("google", scope)

	RegisterProvider(Provider{
		Name:   "google",
		Type:   AuthTypeOAuth2,
		Scopes: []Scope{scope}, // Scope already in initial list
	})

	// Request scope again after registration
	RequestScope("google", scope)

	p, ok := GetProvider("google")
	if !ok {
		t.Fatalf("expected provider 'google' to be registered")
	}

	if len(p.Scopes) != 1 {
		t.Fatalf("expected exactly 1 scope (no duplicates), got %d", len(p.Scopes))
	}
}
