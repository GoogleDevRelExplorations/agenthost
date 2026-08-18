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

package calendar

import (
	"context"
	"fmt"
	"time"

	"github.com/GoogleDevRelExplorations/agenthost/auth"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"google.golang.org/adk/tool"
	"google.golang.org/adk/tool/functiontool"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
)

// ReadCalendarArgs defines the inputs expected by the read_calendar tool.
type ReadCalendarArgs struct {
	// Date is the target date to retrieve meetings for (in YYYY-MM-DD format).
	// Defaults to today's date if not provided.
	Date string `json:"date,omitempty"`
}

// Meeting represents a single calendar event.
type Meeting struct {
	Summary        string `json:"summary"`
	StartTime      string `json:"start_time"`
	EndTime        string `json:"end_time"`
	Location       string `json:"location,omitempty"`
	Description    string `json:"description,omitempty"`
	ResponseStatus string `json:"response_status"`
}

// ReadCalendarResult defines the outputs returned by the read_calendar tool.
type ReadCalendarResult struct {
	Meetings []Meeting `json:"meetings"`
}

// NewReadCalendarTool constructs an ADK function tool that queries a user's primary calendar events.
func NewReadCalendarTool() (tool.Tool, error) {
	return functiontool.New(
		functiontool.Config{
			Name:        "read_calendar",
			Description: "Retrieves scheduled meetings from the user's primary Google Calendar for a specific date or defaults to today.",
		},
		func(ctx tool.Context, args ReadCalendarArgs) (ReadCalendarResult, error) {
			return readCalendarHandler(ctx, args)
		},
	)
}

// readCalendarHandler performs the core lookup logic, separated for easier unit testing.
func readCalendarHandler(ctx context.Context, args ReadCalendarArgs) (ReadCalendarResult, error) {
	callCtx, ok := a2asrv.CallContextFrom(ctx)
	if !ok || callCtx.User == nil || callCtx.User.Name == "" {
		return ReadCalendarResult{}, fmt.Errorf("authentication error: user is not authenticated")
	}
	userEmail := callCtx.User.Name

	client, err := auth.NewClient("google")
	if err != nil {
		return ReadCalendarResult{}, fmt.Errorf("failed to retrieve authenticated HTTP client: %w", err)
	}

	srv, err := calendar.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return ReadCalendarResult{}, fmt.Errorf("failed to initialize Google Calendar client: %w", err)
	}

	var targetDate time.Time
	if args.Date != "" {
		targetDate, err = time.Parse("2006-01-02", args.Date)
		if err != nil {
			return ReadCalendarResult{}, fmt.Errorf("invalid date format (expected YYYY-MM-DD): %w", err)
		}
	} else {
		targetDate = time.Now()
	}

	year, month, day := targetDate.Date()
	loc := targetDate.Location()
	timeMin := time.Date(year, month, day, 0, 0, 0, 0, loc)
	timeMax := time.Date(year, month, day, 23, 59, 59, 999999999, loc)

	events, err := srv.Events.List("primary").
		Context(ctx).
		TimeMin(timeMin.Format(time.RFC3339)).
		TimeMax(timeMax.Format(time.RFC3339)).
		SingleEvents(true).
		OrderBy("startTime").
		Do()
	if err != nil {
		return ReadCalendarResult{}, fmt.Errorf("failed to fetch calendar events: %w", err)
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
		for _, attendee := range item.Attendees {
			if attendee.Self || attendee.Email == userEmail {
				responseStatus = attendee.ResponseStatus
				break
			}
		}

		meetings = append(meetings, Meeting{
			Summary:        item.Summary,
			StartTime:      startTime,
			EndTime:        endTime,
			Location:       item.Location,
			Description:    item.Description,
			ResponseStatus: responseStatus,
		})
	}

	return ReadCalendarResult{Meetings: meetings}, nil
}
