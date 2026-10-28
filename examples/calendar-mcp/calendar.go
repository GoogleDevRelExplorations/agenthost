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
	"fmt"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	_ "github.com/GoogleDevRelExplorations/agenthost/auth/providers/google"
	"github.com/GoogleDevRelExplorations/agenthost/auth/registry"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	googlecalendar "google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

func init() {
	auth.RequestScope("google", registry.Scope{
		Value:       googlecalendar.CalendarReadonlyScope,
		Name:        "Google Calendar (readonly)",
		Description: "allows read access to your calendars.",
		Default:     true,
	})
}

// ReadCalendarArgs defines the input arguments for the read_calendar tool.
type ReadCalendarArgs struct {
	// Date is the target date to retrieve meetings for (in YYYY-MM-DD format).
	// Defaults to today's date if not provided.
	Date string `json:"date,omitempty" jsonschema:"Target date to retrieve meetings for in YYYY-MM-DD format. Defaults to today."`
	// CalendarID is the ID of the calendar to query. Defaults to 'primary'.
	CalendarID string `json:"calendar_id,omitempty" jsonschema:"The calendar identifier to retrieve events from. Defaults to 'primary'."`
}

// Attendee represents a participant in a calendar event.
type Attendee struct {
	Email          string `json:"email"`
	DisplayName    string `json:"display_name,omitempty"`
	ResponseStatus string `json:"response_status,omitempty"`
	Self           bool   `json:"self,omitempty"`
	Organizer      bool   `json:"organizer,omitempty"`
}

// Meeting represents a single calendar event.
type Meeting struct {
	ID             string     `json:"id,omitempty"`
	Summary        string     `json:"summary"`
	StartTime      string     `json:"start_time"`
	EndTime        string     `json:"end_time"`
	Location       string     `json:"location,omitempty"`
	Description    string     `json:"description,omitempty"`
	ResponseStatus string     `json:"response_status"`
	ConferenceLink string     `json:"conference_link,omitempty"`
	Attendees      []Attendee `json:"attendees,omitempty"`
}

// ReadCalendarResult defines the outputs returned by the read_calendar tool.
type ReadCalendarResult struct {
	Date     string    `json:"date"`
	Calendar string    `json:"calendar"`
	Meetings []Meeting `json:"meetings"`
}

// UserInfoResult defines output for get_user_info tool.
type UserInfoResult struct {
	Email               string   `json:"email"`
	Authenticated       bool     `json:"authenticated"`
	AuthorizedProviders []string `json:"authorized_providers"`
	Message             string   `json:"message,omitempty"`
}

// CalendarServiceFactory allows injecting mock services during testing.
type CalendarServiceFactory func(ctx context.Context) (*googlecalendar.Service, error)

var defaultCalendarServiceFactory = func(ctx context.Context) (*googlecalendar.Service, error) {
	client, err := auth.NewClient("google")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authenticated HTTP client: %w", err)
	}
	return googlecalendar.NewService(ctx, option.WithHTTPClient(client))
}

var calendarServiceFactory = defaultCalendarServiceFactory

func readCalendarHandler(ctx context.Context, req *mcp.CallToolRequest, args ReadCalendarArgs) (*mcp.CallToolResult, ReadCalendarResult, error) {
	provider, ok := auth.DelegatedAuthProviderFrom(ctx)
	if !ok || provider == nil || provider.Email() == "" {
		return nil, ReadCalendarResult{}, fmt.Errorf("authentication required: user is not authenticated. Please log in at /login or provide a valid Bearer token")
	}

	userEmail := provider.Email()
	calID := args.CalendarID
	if calID == "" {
		calID = "primary"
	}

	srv, err := calendarServiceFactory(ctx)
	if err != nil {
		return nil, ReadCalendarResult{}, fmt.Errorf("failed to initialize Google Calendar client: %w", err)
	}

	var targetDate time.Time
	if args.Date != "" {
		targetDate, err = time.Parse("2006-01-02", args.Date)
		if err != nil {
			return nil, ReadCalendarResult{}, fmt.Errorf("invalid date format %q (expected YYYY-MM-DD): %w", args.Date, err)
		}
	} else {
		targetDate = time.Now()
	}

	year, month, day := targetDate.Date()
	loc := targetDate.Location()
	timeMin := time.Date(year, month, day, 0, 0, 0, 0, loc)
	timeMax := time.Date(year, month, day, 23, 59, 59, 999999999, loc)

	events, err := srv.Events.List(calID).
		Context(ctx).
		TimeMin(timeMin.Format(time.RFC3339)).
		TimeMax(timeMax.Format(time.RFC3339)).
		SingleEvents(true).
		OrderBy("startTime").
		Do()
	if err != nil {
		return nil, ReadCalendarResult{}, fmt.Errorf("failed to fetch calendar events (ensure calendar is authorized at /authorize/google): %w", err)
	}

	var meetings []Meeting
	for _, item := range events.Items {
		if item.Status == "cancelled" {
			continue
		}

		startTime := ""
		if item.Start != nil {
			if item.Start.DateTime != "" {
				startTime = item.Start.DateTime
			} else {
				startTime = item.Start.Date + " (All day)"
			}
		}

		endTime := ""
		if item.End != nil {
			if item.End.DateTime != "" {
				endTime = item.End.DateTime
			} else {
				endTime = item.End.Date + " (All day)"
			}
		}

		responseStatus := "needsAction"
		if item.Organizer != nil && (item.Organizer.Self || item.Organizer.Email == userEmail) {
			responseStatus = "accepted"
		}

		var attendees []Attendee
		for _, att := range item.Attendees {
			if att.Self || att.Email == userEmail {
				responseStatus = att.ResponseStatus
			}
			attendees = append(attendees, Attendee{
				Email:          att.Email,
				DisplayName:    att.DisplayName,
				ResponseStatus: att.ResponseStatus,
				Self:           att.Self || att.Email == userEmail,
				Organizer:      att.Organizer,
			})
		}

		confLink := item.HangoutLink
		if confLink == "" && item.ConferenceData != nil {
			for _, ep := range item.ConferenceData.EntryPoints {
				if ep.EntryPointType == "video" {
					confLink = ep.Uri
					break
				}
			}
		}

		meetings = append(meetings, Meeting{
			ID:             item.Id,
			Summary:        item.Summary,
			StartTime:      startTime,
			EndTime:        endTime,
			Location:       item.Location,
			Description:    item.Description,
			ResponseStatus: responseStatus,
			ConferenceLink: confLink,
			Attendees:      attendees,
		})
	}

	res := ReadCalendarResult{
		Date:     targetDate.Format("2006-01-02"),
		Calendar: calID,
		Meetings: meetings,
	}
	return nil, res, nil
}

func getUserInfoHandler(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, UserInfoResult, error) {
	provider, ok := auth.DelegatedAuthProviderFrom(ctx)
	if !ok || provider == nil || provider.Email() == "" {
		return nil, UserInfoResult{
			Authenticated: false,
			Message:       "Not authenticated. Please log in via /login or pass an Authorization Bearer header.",
		}, nil
	}

	var authorized []string
	for _, p := range provider.Providers() {
		if _, err := provider.GetCredential(ctx, p); err == nil {
			authorized = append(authorized, p)
		}
	}

	return nil, UserInfoResult{
		Email:               provider.Email(),
		Authenticated:       true,
		AuthorizedProviders: authorized,
		Message:             "Authenticated successfully.",
	}, nil
}
