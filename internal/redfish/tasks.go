package redfish

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// Outcome is the verdict of a task poll.
type Outcome int

const (
	// OutcomeScheduled: accepted and waiting (typically for a reboot).
	OutcomeScheduled Outcome = iota + 1
	// OutcomeCompleted: finished successfully.
	OutcomeCompleted
	// OutcomeFailed: ended in an error state.
	OutcomeFailed
)

// TaskResult describes the last observed task state.
type TaskResult struct {
	Outcome       Outcome
	State, Status string
	Detail        string
}

// WaitTask polls a task monitor URI (taken verbatim from a Location header)
// until the task is scheduled, completed or failed, honouring Retry-After.
// "New"/"Scheduled" with status OK is success-pending: BIOS changes wait for
// the next reboot, so the task never leaves that state by itself.
func (c *Client) WaitTask(ctx context.Context, location string) (TaskResult, error) {
	deadline := time.Now().Add(c.opts.TaskTimeout)
	for {
		resp, err := c.Do(ctx, http.MethodGet, location, nil, nil)
		if err != nil {
			return TaskResult{}, fmt.Errorf("failed to get task status: %w", err)
		}
		var t struct {
			TaskState  string `json:"TaskState"`
			TaskStatus string `json:"TaskStatus"`
			Name       string `json:"Name"`
			Oem        struct {
				Dell struct {
					Message  string `json:"Message"`
					JobState string `json:"JobState"`
					JobType  string `json:"JobType"`
				} `json:"Dell"`
			} `json:"Oem"`
		}
		if len(bytes.TrimSpace(resp.Body)) > 0 {
			if err := json.Unmarshal(resp.Body, &t); err != nil {
				return TaskResult{}, fmt.Errorf("failed to parse task status response: %w", err)
			}
		}
		res := TaskResult{State: t.TaskState, Status: t.TaskStatus,
			Detail: fmt.Sprintf("State: %s, Status: %s, Name: %s", t.TaskState, t.TaskStatus, t.Name)}
		if d := t.Oem.Dell; d.JobState != "" {
			res.Detail += fmt.Sprintf(". Messages: Dell.%s.%s: %s", d.JobType, d.JobState, d.Message)
		}
		switch t.TaskState {
		case "New", "Scheduled":
			res.Outcome = OutcomeScheduled
			if t.TaskStatus != "OK" {
				res.Outcome = OutcomeFailed
			}
			return res, nil
		case "Completed":
			res.Outcome = OutcomeCompleted
			if t.TaskStatus != "" && t.TaskStatus != "OK" {
				res.Outcome = OutcomeFailed
			}
			return res, nil
		case "Exception", "Killed", "Cancelled", "Interrupted":
			res.Outcome = OutcomeFailed
			return res, nil
		}
		wait := c.opts.PollInterval
		if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && ra > 0 {
			wait = time.Duration(ra) * time.Second
		}
		if time.Now().Add(wait).After(deadline) {
			return res, fmt.Errorf("task still %q after %s", res.State, c.opts.TaskTimeout)
		}
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		case <-time.After(wait):
		}
	}
}
