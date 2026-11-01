// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package cert

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"software.sslmate.com/src/go-pkcs12"
)

func TestParseSANLists(t *testing.T) {
	tests := []struct {
		name        string
		dnsInput    string
		ipInput     string
		wantDNS     []string
		wantIPs     []string
		expectError bool
	}{
		{
			name:        "Standard DNS and IPs",
			dnsInput:    "localhost, *.internal.dev, service.local",
			ipInput:     "127.0.0.1, 10.0.0.1, ::1",
			wantDNS:     []string{"localhost", "*.internal.dev", "service.local"},
			wantIPs:     []string{"127.0.0.1", "10.0.0.1", "::1"},
			expectError: false,
		},
		{
			name:        "IP entered in DNS field is reclassified",
			dnsInput:    "example.com, 192.168.1.1",
			ipInput:     "",
			wantDNS:     []string{"example.com"},
			wantIPs:     []string{"192.168.1.1"},
			expectError: false,
		},
		{
			name:        "Invalid IP in IP list returns error",
			dnsInput:    "example.com",
			ipInput:     "not-an-ip",
			expectError: true,
		},
		{
			name:        "Empty strings produce empty slices",
			dnsInput:    "",
			ipInput:     "",
			wantDNS:     nil,
			wantIPs:     nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dns, ips, err := ParseSANLists(tt.dnsInput, tt.ipInput)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(dns) != len(tt.wantDNS) {
				t.Errorf("DNS count mismatch: got %v, want %v", dns, tt.wantDNS)
			}
			for i := range dns {
				if dns[i] != tt.wantDNS[i] {
					t.Errorf("DNS[%d]: got %q, want %q", i, dns[i], tt.wantDNS[i])
				}
			}

			if len(ips) != len(tt.wantIPs) {
				t.Errorf("IP count mismatch: got %v, want %v", ips, tt.wantIPs)
			}
			for i := range ips {
				if ips[i].String() != tt.wantIPs[i] {
					t.Errorf("IP[%d]: got %q, want %q", i, ips[i].String(), tt.wantIPs[i])
				}
			}
		})
	}
}

func TestGeneratePKIHierarchy(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		Role:               RoleCALeaf,
		KeyType:            KeyTypeECDSAP256,
		CommonName:         "app.internal",
		RootCACommonName:   "Internal Enterprise Root CA",
		Organization:       "ACME Corp",
		Country:            "US",
		DNSNames:           []string{"localhost", "service.internal"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5")},
		ValidityDays:       365,
		RootCAValidityDays: 3650,
		OutputDir:          tempDir,
		CertFileName:       "cert.pem",
		KeyFileName:        "key.pem",
		RootCAFileName:     "rootCA.pem",
		RootKeyFileName:    "rootCA-key.pem",
		ChainFileName:      "chain.pem",
		GeneratePKCS12:     true,
		PKCS12FileName:     "bundle.p12",
		PKCS12Password:     "secret123",
	}

	res, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate PKI hierarchy failed: %v", err)
	}

	if !res.IsPKI {
		t.Fatalf("Expected res.IsPKI to be true")
	}

	// 1. Verify Root CA
	caCert, err := x509.ParseCertificate(res.RootCADER)
	if err != nil {
		t.Fatalf("Failed to parse Root CA DER: %v", err)
	}
	if !caCert.IsCA {
		t.Errorf("Root CA certificate must have IsCA = true")
	}
	if caCert.Subject.CommonName != "Internal Enterprise Root CA" {
		t.Errorf("Root CA CN mismatch: got %q", caCert.Subject.CommonName)
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("Root CA must have KeyUsageCertSign")
	}

	// 2. Verify Leaf Certificate
	leafCert, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("Failed to parse Leaf certificate DER: %v", err)
	}
	if leafCert.IsCA {
		t.Errorf("Leaf certificate must not be a CA")
	}
	if leafCert.Subject.CommonName != "app.internal" {
		t.Errorf("Leaf CN mismatch: got %q", leafCert.Subject.CommonName)
	}

	// 3. Verify Leaf signature is signed by the Root CA!
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Cryptographic verification failed: Leaf cert was not signed by Root CA: %v", err)
	}

	// 4. Verify Root CA self-signature
	if err := caCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Root CA self-signature verification failed: %v", err)
	}

	// 5. Verify all files exist in output folder
	expectedFiles := []string{
		"rootCA.pem",
		"rootCA-key.pem",
		"cert.pem",
		"key.pem",
		"chain.pem",
		"bundle.p12",
	}
	for _, f := range expectedFiles {
		p := res.RootCAPath
		switch f {
		case "rootCA.pem":
			p = res.RootCAPath
		case "rootCA-key.pem":
			p = res.RootCAKeyPath
		case "cert.pem":
			p = res.CertPath
		case "key.pem":
			p = res.KeyPath
		case "chain.pem":
			p = res.ChainPath
		case "bundle.p12":
			p = res.PKCS12Path
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("Expected file %s not found at %s: %v", f, p, err)
		} else if (f == "key.pem" || f == "rootCA-key.pem" || f == "bundle.p12") && runtime.GOOS != "windows" {
			if info.Mode().Perm() != 0600 {
				t.Errorf("File %s permissions should be 0600, got %o", f, info.Mode().Perm())
			}
		}
	}

	// 6. Verify PKCS#12 bundle contains both Leaf and CA cert
	p12PrivKey, p12Cert, caList, err := pkcs12.DecodeChain(res.PKCS12Bundle, "secret123")
	if err != nil {
		t.Fatalf("pkcs12.DecodeChain failed: %v", err)
	}
	if p12Cert.Subject.CommonName != "app.internal" {
		t.Errorf("P12 cert CommonName mismatch: %s", p12Cert.Subject.CommonName)
	}
	if len(caList) == 0 || caList[0].Subject.CommonName != "Internal Enterprise Root CA" {
		t.Errorf("P12 CA chain missing Root CA: %v", caList)
	}
	if _, ok := p12PrivKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("P12 private key is not ECDSA")
	}

	// 7. Verify TLS key pair loads
	tlsCert, err := tls.X509KeyPair(res.CertificatePEM, res.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Errorf("tls.Certificate is empty")
	}
}

func TestGenerateWithExistingRootCA(t *testing.T) {
	caDir := t.TempDir()
	outDir := t.TempDir()

	// Step 1: Generate an existing Root CA
	caCfg := Config{
		Role:         RoleCA,
		KeyType:      KeyTypeRSA2048,
		CommonName:   "Existing Corporate Root CA",
		Organization: "Corp IT",
		ValidityDays: 3650,
		OutputDir:    caDir,
		CertFileName: "rootCA.pem",
		KeyFileName:  "rootCA-key.pem",
	}
	caRes, err := Generate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate initial CA: %v", err)
	}

	// Step 2: Use the existing CA to sign a new leaf certificate
	leafCfg := Config{
		Role:               RoleExistingCA,
		KeyType:            KeyTypeECDSAP256,
		CommonName:         "portal.corp.internal",
		ExistingCACertPath: caRes.CertPath,
		ExistingCAKeyPath:  caRes.KeyPath,
		DNSNames:           []string{"portal.corp.internal", "portal.local"},
		IPAddresses:        []net.IP{net.ParseIP("10.50.0.1")},
		ValidityDays:       90,
		OutputDir:          outDir,
		CertFileName:       "portal.crt",
		KeyFileName:        "portal.key",
		ChainFileName:      "portal-chain.crt",
		GeneratePKCS12:     true,
		PKCS12FileName:     "portal.pfx",
		PKCS12Password:     "corp123",
	}

	res, err := Generate(leafCfg)
	if err != nil {
		t.Fatalf("Failed to generate certificate with existing CA: %v", err)
	}

	if !res.IsPKI || !res.IsExistingCA {
		t.Errorf("Expected IsPKI=true and IsExistingCA=true")
	}

	// Verify leaf is signed by the existing CA
	caCert, err := x509.ParseCertificate(caRes.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}

	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Signature verification failed: Leaf cert was not signed by existing CA: %v", err)
	}

	if leafCert.Subject.CommonName != "portal.corp.internal" {
		t.Errorf("Leaf CommonName = %s, want 'portal.corp.internal'", leafCert.Subject.CommonName)
	}

	// Verify chain file exists and contains both certificates
	chainPath := filepath.Join(outDir, "portal-chain.crt")
	chainData, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("Failed to read chain file: %v", err)
	}
	if len(chainData) == 0 {
		t.Errorf("Chain file is empty")
	}

	// Verify PKCS#12 bundle
	p12Path := filepath.Join(outDir, "portal.pfx")
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, chain, err := pkcs12.DecodeChain(p12Data, "corp123")
	if err != nil {
		t.Fatalf("Failed to decode PKCS#12 chain: %v", err)
	}
	if len(chain) == 0 || chain[0].Subject.CommonName != "Existing Corporate Root CA" {
		t.Errorf("PKCS#12 chain missing existing Root CA")
	}

	// Step 3: Test LoadExistingCA validation errors
	// A. Non-existent file
	if _, _, _, err := LoadExistingCA("bad-cert.pem", "bad-key.pem", ""); err == nil {
		t.Errorf("Expected error for non-existent cert, got nil")
	}

	// B. Key mismatch: Create another key and try to use it with caCert
	wrongPriv, _, _, _ := generateKeyPair(KeyTypeRSA2048)
	wrongKeyPEM, _ := encodePrivateKey(wrongPriv, "pkcs8")
	wrongKeyFile := filepath.Join(caDir, "wrong-key.pem")
	_ = os.WriteFile(wrongKeyFile, wrongKeyPEM, 0600)

	if _, _, _, err := LoadExistingCA(caRes.CertPath, wrongKeyFile, ""); err == nil {
		t.Errorf("Expected error when private key does not match CA cert, got nil")
	}
}

func TestGenerateStandaloneCA(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		Role:         RoleCA,
		KeyType:      KeyTypeRSA4096,
		CommonName:   "Standalone Root CA",
		Organization: "Internal Infrastructure",
		Country:      "IN",
		ValidityDays: 1825,
		OutputDir:    tempDir,
		CertFileName: "ca.crt",
		KeyFileName:  "ca.key",
		KeyFormat:    "traditional",
	}

	res, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate CA failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	if !parsedCert.IsCA {
		t.Errorf("CA certificate must have IsCA = true")
	}
	if parsedCert.MaxPathLen != 1 {
		t.Errorf("Expected MaxPathLen = 1, got %d", parsedCert.MaxPathLen)
	}

	expectedUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if parsedCert.KeyUsage&expectedUsage != expectedUsage {
		t.Errorf("KeyUsage missing flags: %v", parsedCert.KeyUsage)
	}

	rsaKey, ok := res.PrivateKey.(*rsa.PrivateKey)
	if !ok || rsaKey.N.BitLen() != 4096 {
		t.Fatalf("Expected 4096-bit RSA key")
	}

	if err := parsedCert.CheckSignatureFrom(parsedCert); err != nil {
		t.Errorf("CA self-signature verification failed: %v", err)
	}
}

func TestGenerateStandaloneLeaf(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		Role:         RoleLeaf,
		KeyType:      KeyTypeECDSAP384,
		CommonName:   "p384.internal",
		OutputDir:    tempDir,
		CertFileName: "p384.pem",
		KeyFileName:  "p384.key",
	}
	res, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate P-384 failed: %v", err)
	}
	certP384, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("Parse P-384 failed: %v", err)
	}
	if err := certP384.CheckSignature(certP384.SignatureAlgorithm, certP384.RawTBSCertificate, certP384.Signature); err != nil {
		t.Errorf("P-384 signature verification failed: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		CommonName: "",
		OutputDir:  tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for empty CN, got nil")
	}

	cfg = Config{
		CommonName: "test.local",
		Country:    "USA",
		OutputDir:  tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for 3-letter Country code, got nil")
	}

	cfg = Config{
		CommonName:   "test.local",
		ValidityDays: 4000,
		OutputDir:    tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for validity > 3650 days, got nil")
	}
}
