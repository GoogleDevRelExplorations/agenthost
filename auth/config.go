package auth

import "github.com/GoogleDevRelExplorations/agenthost/auth/registry"

// Re-export registry types and functions for package backwards compatibility
type Scope = registry.Scope
type Provider = registry.Provider

var RegisterProvider = registry.RegisterProvider
var GetProvider = registry.GetProvider
var RequestScope = registry.RequestScope
