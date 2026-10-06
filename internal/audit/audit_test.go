package audit

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWritesJSONLinesWithMode0600AndAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.log")
	if err := os.WriteFile(path, []byte("{\"old\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var console bytes.Buffer
	l, closeLog, err := Open(path, slog.LevelInfo, slog.NewTextHandler(&console, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hello", "k", "v")
	if err := closeLog(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(b), "{\"old\":1}\n") || !strings.Contains(string(b), `"msg":"hello"`) || !strings.Contains(string(b), `"k":"v"`) {
		t.Errorf("log = %q", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if console.Len() != 0 {
		t.Errorf("an Info event must not reach a Warn console: %q", console.String())
	}
}

func TestOpenWithoutPathOnlyUsesTheConsole(t *testing.T) {
	var console bytes.Buffer
	l, closeLog, err := Open("", slog.LevelInfo, slog.NewTextHandler(&console, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err != nil {
		t.Fatal(err)
	}
	l.Warn("careful")
	if err := closeLog(); err != nil || !strings.Contains(console.String(), "careful") {
		t.Errorf("err = %v, console = %q", err, console.String())
	}
}

func TestRunIDIsUnique(t *testing.T) {
	if a, b := NewRunID(), NewRunID(); a == b || len(a) != 16 {
		t.Errorf("ids %q %q", a, b)
	}
}

func TestFileSHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(p, []byte("abc"), 0o600)
	if got := FileSHA256(p); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Errorf("got %s", got)
	}
	if FileSHA256(filepath.Join(t.TempDir(), "absent")) != "" {
		t.Error("an unreadable file has no hash")
	}
}
