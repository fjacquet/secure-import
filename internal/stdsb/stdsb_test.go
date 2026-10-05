package stdsb

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestToPEMConvertsDERAndPassesPEMThrough(t *testing.T) {
	der := testCertDER(t)
	got, err := ToPEM(der)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(got)
	if block == nil || block.Type != "CERTIFICATE" || string(block.Bytes) != string(der) {
		t.Fatalf("DER was not converted to an equivalent PEM: %q", got)
	}
	again, err := ToPEM(got)
	if err != nil || string(again) != string(got) {
		t.Errorf("PEM input must pass through unchanged, err = %v", err)
	}
	if DERLen(got) != len(der) {
		t.Errorf("DERLen = %d, want %d", DERLen(got), len(der))
	}
}

func TestToPEMRejectsGarbageAndEmpty(t *testing.T) {
	for _, in := range [][]byte{[]byte("garbage"), nil} {
		if _, err := ToPEM(in); err == nil || !strings.Contains(err.Error(), "not a PEM or DER certificate") {
			t.Errorf("ToPEM(%q) err = %v", in, err)
		}
	}
}

func TestToPEMRejectsPrivateKeyAndKeepsOnlyCertificates(t *testing.T) {
	key := []byte("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n")
	if _, err := ToPEM(key); err == nil {
		t.Error("a private key must be rejected")
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertDER(t)})
	out, err := ToPEM(append([]byte("Certificate:\n  text dump\n"), cert...))
	if err != nil || !bytes.HasPrefix(out, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Contains(out, []byte("text dump")) {
		t.Errorf("out = %q, err = %v", out, err)
	}
	if _, err := ToPEM(append(cert, key...)); err == nil {
		t.Error("a bundle holding a private key must be rejected")
	}
}
