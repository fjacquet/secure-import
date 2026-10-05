package redfish

import "testing"

func TestParseMessagesTopLevelAndErrorEnvelope(t *testing.T) {
	ok := []byte(`{"@Message.ExtendedInfo":[{"MessageId":"Base.1.12.Success","Message":"The request completed successfully.","Severity":"OK","Resolution":"None"},{"MessageId":"IDRAC.2.9.SYS430","Message":"done","Severity":"OK","Resolution":"Restart the server."}]}`)
	msgs := ParseMessages(ok)
	if len(msgs) != 2 || msgs[1].ID != "IDRAC.2.9.SYS430" || msgs[1].Resolution != "Restart the server." {
		t.Fatalf("msgs = %+v", msgs)
	}
	bad := []byte(`{"error":{"@Message.ExtendedInfo":[{"MessageId":"IDRAC.2.9.SYS011","Message":"Pending configuration values are already committed","Severity":"Warning"}]}}`)
	if msgs := ParseMessages(bad); len(msgs) != 1 || msgs[0].ID != "IDRAC.2.9.SYS011" {
		t.Fatalf("error envelope: msgs = %+v", msgs)
	}
	for _, in := range []string{"", "not json", "{}"} {
		if msgs := ParseMessages([]byte(in)); len(msgs) != 0 {
			t.Errorf("ParseMessages(%q) = %+v, want none", in, msgs)
		}
	}
}

func TestIsSuccessIDIsVersionAgnosticAndCaseInsensitive(t *testing.T) {
	yes := []string{"Base.1.0.Success", "Base.1.12.Success", "IDRAC.2.9.SYS430", "iDRAC.1.6.SYS413", "iDRAC.1.6.SYS431", "Bios.1.0.BiosPropertyModified", "base.1.5.success"}
	no := []string{"Base.1.12.ResourceMissingAtURI", "IDRAC.2.9.SYS011", "Base.Success", ""}
	for _, id := range yes {
		if !IsSuccessID(id) {
			t.Errorf("IsSuccessID(%q) = false, want true", id)
		}
	}
	for _, id := range no {
		if IsSuccessID(id) {
			t.Errorf("IsSuccessID(%q) = true, want false", id)
		}
	}
}

// IDRAC.2.9.SYS403 ("resource not found", Critical) matches the SYS4xx success
// pattern, so severity must be part of the verdict. The Python script missed this.
func TestIsSuccessRequiresANonCriticalSeverity(t *testing.T) {
	cases := []struct {
		m    Message
		want bool
	}{
		{Message{ID: "IDRAC.2.9.SYS430", Severity: "OK"}, true},
		{Message{ID: "IDRAC.2.9.SYS430"}, true},
		{Message{ID: "Base.1.12.Success", Severity: "OK"}, true},
		{Message{ID: "IDRAC.2.9.SYS403", Severity: "Critical"}, false},
		{Message{ID: "IDRAC.2.9.SYS403", Severity: "critical"}, false},
		{Message{ID: "Base.1.12.ResourceMissingAtURI", Severity: "Critical"}, false},
	}
	for _, tc := range cases {
		if got := IsSuccess(tc.m); got != tc.want {
			t.Errorf("IsSuccess(%+v) = %v, want %v", tc.m, got, tc.want)
		}
	}
}

func TestNeedsRebootAndSummarize(t *testing.T) {
	msgs := []Message{{Text: "ok", Severity: "OK", Resolution: "None"}, {Text: "x", Severity: "Warning", Resolution: "Reboot the computer system."}}
	if !NeedsReboot(msgs) {
		t.Error("NeedsReboot = false, want true (Resolution mentions Reboot)")
	}
	if NeedsReboot(msgs[:1]) {
		t.Error("NeedsReboot = true, want false")
	}
	if got := Summarize(msgs); got != "OK: ok; Warning: x" {
		t.Errorf("Summarize = %q", got)
	}
}
