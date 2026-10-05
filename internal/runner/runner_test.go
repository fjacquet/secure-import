package runner

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sbmgr/internal/inventory"
	"sbmgr/internal/platform"
	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

const sessionURI = "/redfish/v1/SessionService/Sessions/1"

func lenovoBMC(t *testing.T) *testbmc.Server {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish("Lenovo", "1", "XCC", "6.0")
	s.StdSecureBoot("1", false, "SetupMode", 1)
	return s
}

func host(s *testbmc.Server) inventory.Host {
	return inventory.Host{IP: s.URL, Username: "USERID", Password: "secret-pw"}
}

func opts(action string) Options {
	return Options{Action: action, Platform: "auto", Concurrency: 2, Client: redfish.Options{Timeout: 2 * time.Second}}
}

// Review Focus 3 and 4: one dead BMC does not stop the others, rows keep input
// order, and every session that was opened is closed.
func TestRunIsolatesFailuresKeepsOrderAndClosesSessions(t *testing.T) {
	a, b := lenovoBMC(t), lenovoBMC(t)
	dead := testbmc.New(t)
	dead.Close()
	res := Run(context.Background(), []inventory.Host{host(a), host(dead), host(b)}, opts(platform.ActionStatus))
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	if !res[0].Success || res[0].IP != a.URL || res[0].Platform != "lenovo" {
		t.Errorf("res[0] = %+v", res[0])
	}
	if res[1].Success || res[1].Error == "" || res[1].IP != dead.URL {
		t.Errorf("res[1] = %+v, want an error row for the dead BMC", res[1])
	}
	if !res[2].Success || res[2].IP != b.URL {
		t.Errorf("res[2] = %+v", res[2])
	}
	for _, s := range []*testbmc.Server{a, b} {
		if n := s.Count("DELETE", sessionURI); n != 1 {
			t.Errorf("session DELETE count = %d, want 1", n)
		}
	}
	out, _ := json.Marshal(res)
	if strings.Contains(string(out), "secret-pw") {
		t.Error("results must never contain the password")
	}
}

func TestRunClosesSessionWhenTheActionFails(t *testing.T) {
	s := lenovoBMC(t)
	res := Run(context.Background(), []inventory.Host{host(s)}, opts(platform.ActionPolicyCustom))
	if res[0].Success || !strings.Contains(res[0].Error, "not supported on lenovo") {
		t.Fatalf("res[0] = %+v", res[0])
	}
	if n := s.Count("DELETE", sessionURI); n != 1 {
		t.Errorf("session DELETE count = %d, want 1 even when the action fails", n)
	}
}

func TestRunPassesParamsAndForcedPlatform(t *testing.T) {
	s := testbmc.New(t)
	s.Redfish("Acme", "1", "X", "1") // undetectable vendor
	s.StdSecureBoot("1", false, "SetupMode", 3)
	o := opts(platform.ActionDBList)
	o.Platform = "supermicro"
	res := Run(context.Background(), []inventory.Host{host(s)}, o)
	if !res[0].Success || res[0].CertCount != 3 || res[0].Platform != "supermicro" {
		t.Errorf("res[0] = %+v", res[0])
	}
}

func TestRunWithCancelledContextStillReturnsOneRowPerHost(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hosts := []inventory.Host{{IP: "http://127.0.0.1:1"}, {IP: "http://127.0.0.1:2"}, {IP: "http://127.0.0.1:3"}}
	res := Run(ctx, hosts, opts(platform.ActionStatus))
	if len(res) != 3 {
		t.Fatalf("results = %d, want 3", len(res))
	}
	for i, r := range res {
		if r.Success || r.Error == "" {
			t.Errorf("res[%d] = %+v, want a failure row", i, r)
		}
	}
}
