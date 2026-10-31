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

func TestEndToEndCertGenerationWithRootCA(t *testing.T) {
	tempDir := t.TempDir()

	cfg := cert.Config{
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
		t.Fatalf("Failed to generate certificate hierarchy: %v", err)
	}

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

	for _, p := range []string{certPath, keyPath, chainPath, p12Path} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("Expected file at %s, got: %v", p, err)
		}
	}

	// 3. Verify Leaf cert was signed by the Root CA
	leafPEM, _ := os.ReadFile(certPath)
	keyPEM, _ := os.ReadFile(keyPath)
	tlsKeyPair, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load TLS key pair: %v", err)
	}

	leafCert, err := x509.ParseCertificate(tlsKeyPair.Certificate[0])
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	rootCert, err := x509.ParseCertificate(res.RootCADER)
	if err != nil {
		t.Fatalf("Failed to parse Root CA certificate: %v", err)
	}

	if err := leafCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("Verification failed: leaf is not signed by Root CA: %v", err)
	}

	// 4. Verify PKCS#12 bundle includes Root CA
	p12Bytes, _ := os.ReadFile(p12Path)
	_, _, caChain, err := pkcs12.DecodeChain(p12Bytes, "changeit")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 chain: %v", err)
	}
	if len(caChain) == 0 {
		t.Fatalf("PKCS#12 chain is missing Root CA")
	}

	// 5. Test trust report generation
	report, err := trust.InstallRootCA(res.RootCADER, res.RootCAPEM, rootCertPath, trust.InstallOptions{
		InstallOS:       false,
		InstallBrowsers: false,
	})
	if err != nil {
		t.Fatalf("trust.InstallRootCA failed: %v", err)
	}
	if len(report.ManualCommands) == 0 {
		t.Errorf("Expected manual instructions in trust report")
	}
}

func TestEndToEndWithExistingCA(t *testing.T) {
	caDir := t.TempDir()
	outDir := t.TempDir()

	// 1. Generate Root CA
	caCfg := cert.Config{
		Role:         cert.RoleCA,
		KeyType:      cert.KeyTypeECDSAP256,
		CommonName:   "My Company Root CA",
		ValidityDays: 3650,
		OutputDir:    caDir,
		CertFileName: "rootCA.pem",
		KeyFileName:  "rootCA-key.pem",
	}
	caRes, err := cert.Generate(caCfg)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate Leaf using existing CA
	leafCfg := cert.Config{
		Role:               cert.RoleExistingCA,
		KeyType:            cert.KeyTypeECDSAP256,
		CommonName:         "test.internal",
		ExistingCACertPath: caRes.CertPath,
		ExistingCAKeyPath:  caRes.KeyPath,
		DNSNames:           []string{"test.internal"},
		ValidityDays:       30,
		OutputDir:          outDir,
		CertFileName:       "test.pem",
		KeyFileName:        "test.key",
	}
	leafRes, err := cert.Generate(leafCfg)
	if err != nil {
		t.Fatal(err)
	}

	if !leafRes.IsExistingCA {
		t.Errorf("Expected IsExistingCA = true")
	}

	caCert, _ := x509.ParseCertificate(caRes.CertificateDER)
	leafCert, _ := x509.ParseCertificate(leafRes.CertificateDER)

	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Leaf was not signed by the existing Root CA: %v", err)
	}
}
