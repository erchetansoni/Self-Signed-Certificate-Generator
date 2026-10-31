package main

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"certgen/internal/cert"
	"certgen/internal/trust"
	"software.sslmate.com/src/go-pkcs12"
)

func TestEndToEndCertGeneration(t *testing.T) {
func TestEndToEndCertGenerationWithRootCA(t *testing.T) {
	tempDir := t.TempDir()

	cfg := cert.Config{
		Role:               cert.RoleLeaf,
		Role:               cert.RoleCALeaf,
		KeyType:            cert.KeyTypeECDSAP256,
		CommonName:         "service.internal",
		RootCACommonName:   "Internal Test Root CA",
		Organization:       "Enterprise IT",
		OrganizationalUnit: "Security Operations",
		Country:            "US",
		DNSNames:           []string{"service.internal", "*.service.internal"},
		IPAddresses:        []net.IP{net.ParseIP("192.168.1.100"), net.ParseIP("127.0.0.1")},
		ValidityDays:       180,
		RootCAValidityDays: 3650,
		OutputDir:          tempDir,
		CertFileName:       "service.crt",
		KeyFileName:        "service.key",
		RootCAFileName:     "rootCA.crt",
		RootKeyFileName:    "rootCA.key",
		ChainFileName:      "chain.crt",
		GeneratePKCS12:     true,
		PKCS12FileName:     "service.p12",
		PKCS12Password:     "changeit",
		KeyFormat:          "pkcs8",
	}

	res, err := cert.Generate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
		t.Fatalf("Failed to generate certificate hierarchy: %v", err)
	}

	// Verify files created
	// 1. Verify Root CA files created in output folder
	rootCertPath := filepath.Join(tempDir, "rootCA.crt")
	rootKeyPath := filepath.Join(tempDir, "rootCA.key")

	if _, err := os.Stat(rootCertPath); err != nil {
		t.Fatalf("Expected Root CA file at %s, got: %v", rootCertPath, err)
	}
	if _, err := os.Stat(rootKeyPath); err != nil {
		t.Fatalf("Expected Root CA key file at %s, got: %v", rootKeyPath, err)
	}

	// 2. Verify Leaf Certificate and chain files created
	certPath := filepath.Join(tempDir, "service.crt")
	keyPath := filepath.Join(tempDir, "service.key")
	chainPath := filepath.Join(tempDir, "chain.crt")
	p12Path := filepath.Join(tempDir, "service.p12")

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("Expected cert file at %s, got: %v", certPath, err)
	for _, p := range []string{certPath, keyPath, chainPath, p12Path} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("Expected file at %s, got: %v", p, err)
		}
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("Expected key file at %s, got: %v", keyPath, err)
	}
	if _, err := os.Stat(p12Path); err != nil {
		t.Fatalf("Expected p12 file at %s, got: %v", p12Path, err)
	}

	// Read and parse PEM
	certPEM, err := os.ReadFile(certPath)
	// 3. Verify Leaf cert was signed by the Root CA
	leafPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	tlsKeyPair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to read cert file: %v", err)
		t.Fatalf("Failed to load TLS key pair: %v", err)
	}
	keyPEM, err := os.ReadFile(keyPath)

	leafCert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	tlsKeyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	rootCert, err := x509.ParseCertificate(res.RootCADER)
	if err != nil {
		t.Fatalf("Failed to load TLS key pair: %v", err)
		t.Fatalf("Failed to parse Root CA certificate: %v", err)
	}
	if len(tlsKeyPair.Certificate) == 0 {
		t.Fatalf("No certificates in TLS key pair")

	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("Verification failed: leaf is not signed by Root CA: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	// 4. Verify PKCS#12 bundle includes Root CA
	p12Bytes, _ := os.ReadFile(p12Path)
	_, _, caChain, err := pkcs12.DecodeChain(p12Bytes, "changeit")
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
		t.Fatalf("Failed to decode PKCS#12 chain: %v", err)
	}

	if parsedCert.Subject.CommonName != "service.internal" {
		t.Errorf("CommonName = %q, want 'service.internal'", parsedCert.Subject.CommonName)
	if len(caChain) == 0 {
		t.Fatalf("PKCS#12 chain is missing Root CA")
	}
	if parsedCert.IsCA {
		t.Errorf("Expected leaf certificate to have IsCA = false")
	}

	// Verify PKCS#12 bundle
	p12Bytes, err := os.ReadFile(p12Path)
	// 5. Test trust report generation
	report, err := trust.InstallRootCA(res.RootCADER, res.RootCAPEM, rootCertPath, trust.InstallOptions{
		InstallOS:       false,
		InstallBrowsers: false,
	})
	if err != nil {
		t.Fatalf("Failed to read p12 file: %v", err)
		t.Fatalf("trust.InstallRootCA failed: %v", err)
	}
	_, p12Cert, err := pkcs12.Decode(p12Bytes, "changeit")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 bundle: %v", err)
	if len(report.ManualCommands) == 0 {
		t.Errorf("Expected manual instructions in trust report")
	}
	if p12Cert.Subject.CommonName != "service.internal" {
		t.Errorf("P12 CommonName = %q, want 'service.internal'", p12Cert.Subject.CommonName)
	}

	if res.FingerprintSHA256 == "" {
		t.Errorf("Fingerprint should not be empty")
	}
}

