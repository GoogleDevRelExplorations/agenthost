package google

import (
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"golang.org/x/oauth2/google"
	analyticsdata "google.golang.org/api/analyticsdata/v1alpha"
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
}
