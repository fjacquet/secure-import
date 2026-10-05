package platform

import (
	"context"
	"errors"
	"testing"
)

func TestIsDBAction(t *testing.T) {
	for _, a := range AllActions {
		want := a == ActionDBList || a == ActionDBImport || a == ActionDBExport || a == ActionDBDelete
		if IsDBAction(a) != want {
			t.Errorf("IsDBAction(%q) = %v, want %v", a, !want, want)
		}
	}
	if len(AllActions) != 9 {
		t.Errorf("AllActions has %d entries, want 9", len(AllActions))
	}
}

func TestUnsupportedReturnsErrUnsupported(t *testing.T) {
	var u Unsupported
	ctx := context.Background()
	if _, err := u.SetSecureBoot(ctx, true); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SetSecureBoot: %v", err)
	}
	if _, err := u.SetPolicy(ctx, "Custom"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("SetPolicy: %v", err)
	}
	if _, err := u.DBList(ctx); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBList: %v", err)
	}
	if _, err := u.DBImport(ctx, "f"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBImport: %v", err)
	}
	if _, err := u.DBExport(ctx, "u", "f"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBExport: %v", err)
	}
	if _, err := u.DBDelete(ctx, "u"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("DBDelete: %v", err)
	}
}

func TestPendingStatus(t *testing.T) {
	if got := PendingStatus("Enabled", true); got != "Enabled (Pending - Reboot Required)" {
		t.Errorf("got %q", got)
	}
	if got := PendingStatus("Disabled", false); got != "Disabled" {
		t.Errorf("got %q", got)
	}
}
