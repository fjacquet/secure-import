package detect

import (
	"context"
	"strings"
	"testing"

	"sbmgr/internal/redfish"
	"sbmgr/internal/testbmc"
)

func client(t *testing.T, vendor, firmware string) *redfish.Client {
	t.Helper()
	s := testbmc.New(t)
	s.Redfish(vendor, "1", "Model", firmware)
	c, err := redfish.New(s.URL, "u", "p", redfish.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAutoDetectionByVendorAndFirmware(t *testing.T) {
	cases := []struct{ vendor, firmware, want string }{
		{"Dell", "7.20.30.50", "idrac9"},
		{"Dell", "4.40.00.00", "idrac9"},
		{"Dell", "3.30.30.30", "idrac9"},
		{"Dell", "1.30.60.50", "idrac10"},
		{"HPE", "1.62", "ilo"},
		{"Hewlett Packard Enterprise", "1.62", "ilo"},
		{"Lenovo", "6.0", "lenovo"},
		{"Supermicro", "1.0", "supermicro"},
		{"Super Micro Computer", "1.0", "supermicro"},
	}
	for _, tc := range cases {
		p, err := New(context.Background(), client(t, tc.vendor, tc.firmware), "auto", "")
		if err != nil || p.Name() != tc.want {
			t.Errorf("%s %s: got %v, %v; want %s", tc.vendor, tc.firmware, p, err, tc.want)
		}
	}
}

func TestDetectionFailuresSuggestPlatformFlag(t *testing.T) {
	for _, tc := range []struct{ vendor, firmware, want string }{
		{"Acme", "1.0", "unknown vendor"},
		{"Dell", "2.1.0.0", "unsupported iDRAC firmware"},
		{"Dell", "abc", "unreadable iDRAC firmware version"},
	} {
		_, err := New(context.Background(), client(t, tc.vendor, tc.firmware), "", "")
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "--platform") {
			t.Errorf("%s %s: err = %v, want %q and a --platform hint", tc.vendor, tc.firmware, err, tc.want)
		}
	}
}

func TestForcedPlatformSkipsDetection(t *testing.T) {
	p, err := New(context.Background(), client(t, "Dell", "7.0.0.0"), "ilo", "")
	if err != nil || p.Name() != "ilo" {
		t.Fatalf("got %v, %v", p, err)
	}
	if _, err := New(context.Background(), client(t, "Dell", "7.0.0.0"), "nope", ""); err == nil || !strings.Contains(err.Error(), "unknown platform") {
		t.Errorf("err = %v", err)
	}
}
