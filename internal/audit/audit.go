// Package audit builds the run log: structured events (log/slog) written to a file
// next to the console output. Events never carry passwords, tokens or request bodies.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
)

// Open returns a logger that writes to console and, when path is not empty, also to
// path as JSON lines (append-only, mode 0600). Each handler applies its own level:
// the file records events at fileLevel and above, the console keeps its own filter.
// The returned function closes the file.
func Open(path string, fileLevel slog.Level, console slog.Handler) (*slog.Logger, func() error, error) {
	if path == "" {
		return slog.New(console), func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if err := f.Chmod(0o600); err != nil { // OpenFile keeps the mode of a file that already exists
		_ = f.Close()
		return nil, nil, err
	}
	file := slog.NewJSONHandler(f, &slog.HandlerOptions{Level: fileLevel})
	return slog.New(slog.NewMultiHandler(console, file)), f.Close, nil
}

// NewRunID returns a random 16-character identifier shared by every event of a run.
func NewRunID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// FileSHA256 returns the hex SHA-256 of a file, or "" when it cannot be read.
func FileSHA256(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
