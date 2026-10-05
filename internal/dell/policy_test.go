package dell

import (
	"context"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/redfish"
)

func TestSetPolicyStagesOnResetAndVerifiesTask(t *testing.T) {
	s, d := newFake9(t, "")
	ch, err := d.SetPolicy(context.Background(), "Custom")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Location != task || ch.JobID != "JID_706967682250" {
		t.Errorf("Location/JobID = %q / %q", ch.Location, ch.JobID)
	}
	if !strings.Contains(ch.Message, "Verification: State: New, Status: OK, Name: Config: Bios") {
		t.Errorf("message = %q", ch.Message)
	}
	var body string
	for _, r := range s.Requests() {
		if r.Method == "PATCH" && r.Path == sys+"/Bios/Settings" {
			body = r.Body
		}
	}
	for _, want := range []string{`"SecureBootPolicy":"Custom"`, `"ApplyTime":"OnReset"`} {
		if !strings.Contains(body, want) {
			t.Errorf("PATCH body %q lacks %s", body, want)
		}
	}
}

// Changelog bug 3: the task is polled where the BMC says (Location), whatever
// the firmware's TaskService layout is.
func TestSetPolicyFollowsLocationUnderTaskMonitors(t *testing.T) {
	s, d := newFake9(t, "")
	mon := "/redfish/v1/TaskService/TaskMonitors/JID_42"
	s.JSONH("PATCH", sys+"/Bios/Settings", 202, map[string]string{"Location": mon}, info("Base.1.12.Success", "None"))
	s.JSON("GET", mon, 200, map[string]any{"TaskState": "Scheduled", "TaskStatus": "OK", "Name": "x"})
	ch, err := d.SetPolicy(context.Background(), "Standard")
	if err != nil || ch.JobID != "JID_42" {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("GET", mon) != 1 || s.Count("GET", task) != 0 {
		t.Error("the Location from the PATCH response must be the only task URI polled")
	}
}

func TestSetPolicyFailedTaskIsAnError(t *testing.T) {
	s, d := newFake9(t, "")
	s.JSON("GET", task, 200, map[string]any{"TaskState": "Exception", "TaskStatus": "Critical", "Name": "x"})
	if _, err := d.SetPolicy(context.Background(), "Custom"); err == nil || !strings.Contains(err.Error(), "task failed") {
		t.Errorf("err = %v", err)
	}
}

func TestSetPolicyNoWaitSkipsTaskPolling(t *testing.T) {
	s, d := newFake9(t, "", redfish.Options{NoWait: true, PollInterval: time.Millisecond})
	ch, err := d.SetPolicy(context.Background(), "Custom")
	if err != nil || ch.Location != task {
		t.Fatalf("ch = %+v, err = %v", ch, err)
	}
	if s.Count("GET", task) != 0 {
		t.Error("--no-wait must not poll the task")
	}
}
