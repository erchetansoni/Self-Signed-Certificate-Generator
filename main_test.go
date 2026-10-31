package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"certgen/internal/cert"
	"software.sslmate.com/src/go-pkcs12"
)

func TestEndToEndCertGeneration(t *testing.T) {
	tempDir := t.TempDir()

	cfg := cert.Config{
		Role:               cert.RoleLeaf,
		KeyType:            cert.KeyTypeECDSAP256,
		CommonName:         "service.internal",
		Organization:       "Enterprise IT",
		OrganizationalUnit: "Security Operations",
		Country:            "US",
		DNSNames:           []string{"service.internal", "*.service.internal"},
		IPAddresses:        []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("127.0.0.1")},
		ValidityDays:       180,
		OutputDir:          tempDir,
		CertFileName:       "service.crt",
		KeyFileName:        "service.key",
		GeneratePKCS12:     true,
		PKCS12FileName:     "service.p12",
		PKCS12Password:     "changeit",
		KeyFormat:          "pkcs8",
	}

	res, err := cert.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Verify files created
	certPath := filepath.Join(tempDir, "service.crt")
	keyPath := filepath.Join(tempDir, "service.key")
	p12Path := filepath.Join(tempDir, "service.p12")

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("Expected cert file at %s, got: %v", certPath, err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("Expected key file at %s, got: %v", keyPath, err)
	}
	if _, err := os.Stat(p12Path); err != nil {
		t.Fatalf("Expected p12 file at %s, got: %v", p12Path, err)
	}

	// Read and parse PEM
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}

	tlsKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load TLS key pair: %v", err)
	}
	if len(tlsKeyPair.Certificate) == 0 {
		t.Fatalf("No certificates in TLS key pair")
	}

	parsedCert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	if parsedCert.Subject.CommonName != "service.internal" {
		t.Errorf("CommonName = %q, want 'service.internal'", parsedCert.Subject.CommonName)
	}
	if parsedCert.IsCA {
		t.Errorf("Expected leaf certificate to have IsCA = false")
	}

	// Verify PKCS#12 bundle
	p12Bytes, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatalf("Failed to read p12 file: %v", err)
	}
	_, p12Cert, err := pkcs12.Decode(p12Bytes, "changeit")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 bundle: %v", err)
	}
	if p12Cert.Subject.CommonName != "service.internal" {
		t.Errorf("P12 CommonName = %q, want 'service.internal'", p12Cert.Subject.CommonName)
	}

	if res.FingerprintSHA256 == "" {
		t.Errorf("Fingerprint should not be empty")
	}
}

