package stdsb

import (
	"bytes"
	"encoding/pem"
	"testing"
)

// FuzzToPEM: whatever a user passes as a certificate file, ToPEM must not panic and
// must only ever return CERTIFICATE blocks (never a private key).
func FuzzToPEM(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{0x30, 0x82, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := ToPEM(data)
		if err != nil {
			return
		}
		blocks := 0
		for rest := out; ; {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			blocks++
			if b.Type != "CERTIFICATE" {
				t.Fatalf("ToPEM returned a %q block", b.Type)
			}
		}
		if blocks == 0 || bytes.Contains(out, []byte("PRIVATE")) {
			t.Fatalf("ToPEM succeeded with %d certificate blocks: %q", blocks, out)
		}
		if _, err := CertSHA256s(data); err != nil {
			t.Fatalf("CertSHA256s failed on input ToPEM accepted: %v", err)
		}
	})
}
