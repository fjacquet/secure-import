package redfish

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sbmgr/internal/testbmc"
)

func taskClient(t *testing.T, s *testbmc.Server) *Client {
	t.Helper()
	c, err := New(s.URL, "u", "p", Options{PollInterval: 5 * time.Millisecond, TaskTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestWaitTaskScheduledStopsAtFirstPoll(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/redfish/v1/TaskService/Tasks/JID_1", 200, map[string]any{"TaskState": "New", "TaskStatus": "OK", "Name": "Config"})
	res, err := taskClient(t, s).WaitTask(context.Background(), "/redfish/v1/TaskService/Tasks/JID_1")
	if err != nil || res.Outcome != OutcomeScheduled {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	if !strings.Contains(res.Detail, "State: New, Status: OK, Name: Config") {
		t.Errorf("detail = %q", res.Detail)
	}
}

func TestWaitTaskFollowsOpaqueLocationUntilCompleted(t *testing.T) {
	s := testbmc.New(t)
	var calls atomic.Int32
	s.Handle("GET", "/redfish/v1/TaskService/TaskMonitors/abc", func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			testbmc.WriteJSON(w, 200, map[string]any{"TaskState": "Running"})
			return
		}
		testbmc.WriteJSON(w, 200, map[string]any{"TaskState": "Completed", "TaskStatus": "OK"})
	})
	res, err := taskClient(t, s).WaitTask(context.Background(), "/redfish/v1/TaskService/TaskMonitors/abc")
	if err != nil || res.Outcome != OutcomeCompleted || calls.Load() != 2 {
		t.Fatalf("res = %+v, err = %v, calls = %d", res, err, calls.Load())
	}
}

func TestWaitTaskFailureAndTimeout(t *testing.T) {
	s := testbmc.New(t)
	s.JSON("GET", "/t/failed", 200, map[string]any{"TaskState": "Exception", "TaskStatus": "Critical", "Name": "N"})
	if res, err := taskClient(t, s).WaitTask(context.Background(), "/t/failed"); err != nil || res.Outcome != OutcomeFailed {
		t.Errorf("failed task: res = %+v, err = %v", res, err)
	}
	s.JSON("GET", "/t/stuck", 200, map[string]any{"TaskState": "Running"})
	if _, err := taskClient(t, s).WaitTask(context.Background(), "/t/stuck"); err == nil || !strings.Contains(err.Error(), "still") {
		t.Errorf("stuck task: err = %v, want timeout error", err)
	}
	if _, err := taskClient(t, s).WaitTask(context.Background(), "/t/missing"); err == nil || !strings.Contains(err.Error(), "failed to get task status") {
		t.Errorf("missing task: err = %v", err)
	}
}
