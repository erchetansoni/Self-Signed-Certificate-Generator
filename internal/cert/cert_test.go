package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

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

func TestGenerateLeafECDSAP256(t *testing.T) {
func TestGeneratePKIHierarchy(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		Role:               RoleLeaf,
		Role:               RoleCALeaf,
		KeyType:            KeyTypeECDSAP256,
		CommonName:         "app.internal",
		RootCACommonName:   "Internal Enterprise Root CA",
		Organization:       "ACME Corp",
		OrganizationalUnit: "Engineering",
		Country:            "US",
		DNSNames:           []string{"localhost", "service.internal"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5")},
		ValidityDays:       30,
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
		t.Fatalf("Generate failed: %v", err)
		t.Fatalf("Generate PKI hierarchy failed: %v", err)
	}

	// 1. Verify Certificate DER parsing
	parsedCert, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("failed to parse certificate DER: %v", err)
	if !res.IsPKI {
		t.Fatalf("Expected res.IsPKI to be true")
	}

	// Subject verification
	if parsedCert.Subject.CommonName != "app.internal" {
		t.Errorf("CN mismatch: got %q, want 'app.internal'", parsedCert.Subject.CommonName)
	// 1. Verify Root CA
	caCert, err := x509.ParseCertificate(res.RootCADER)
	if err != nil {
		t.Fatalf("Failed to parse Root CA DER: %v", err)
	}
	if len(parsedCert.Subject.Organization) == 0 || parsedCert.Subject.Organization[0] != "ACME Corp" {
		t.Errorf("Organization mismatch: %v", parsedCert.Subject.Organization)
	if !caCert.IsCA {
		t.Errorf("Root CA certificate must have IsCA = true")
	}
	if len(parsedCert.Subject.OrganizationalUnit) == 0 || parsedCert.Subject.OrganizationalUnit[0] != "Engineering" {
		t.Errorf("OU mismatch: %v", parsedCert.Subject.OrganizationalUnit)
	if caCert.Subject.CommonName != "Internal Enterprise Root CA" {
		t.Errorf("Root CA CN mismatch: got %q", caCert.Subject.CommonName)
	}
	if len(parsedCert.Subject.Country) == 0 || parsedCert.Subject.Country[0] != "US" {
		t.Errorf("Country mismatch: %v", parsedCert.Subject.Country)
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("Root CA must have KeyUsageCertSign")
	}

	// Basic Constraints
	if parsedCert.IsCA {
	// 2. Verify Leaf Certificate
	leafCert, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("Failed to parse Leaf certificate DER: %v", err)
	}
	if leafCert.IsCA {
		t.Errorf("Leaf certificate must not be a CA")
	}
	if !parsedCert.BasicConstraintsValid {
		t.Errorf("BasicConstraintsValid must be true")
	if leafCert.Subject.CommonName != "app.internal" {
		t.Errorf("Leaf CN mismatch: got %q", leafCert.Subject.CommonName)
	}

	// Key Usages
	if parsedCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Errorf("DigitalSignature KeyUsage must be set")
	// 3. Verify Leaf signature is signed by the Root CA!
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Cryptographic verification failed: Leaf cert was not signed by Root CA: %v", err)
	}
	if parsedCert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Errorf("CertSign KeyUsage must NOT be set for leaf")

	// 4. Verify Root CA self-signature
	if err := caCert.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("Root CA self-signature verification failed: %v", err)
	}

	// ExtKeyUsages
	hasServerAuth := false
	hasClientAuth := false
	for _, eku := range parsedCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
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
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasServerAuth || !hasClientAuth {
		t.Errorf("ExtKeyUsage must include ServerAuth and ClientAuth, got: %v", parsedCert.ExtKeyUsage)
	}

	// SANs (including auto-included CN)
	expectedDNS := []string{"localhost", "service.internal", "app.internal"}
	for _, exp := range expectedDNS {
		found := false
		for _, act := range parsedCert.DNSNames {
			if act == exp {
				found = true
				break
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("Expected file %s not found at %s: %v", f, p, err)
		} else if (f == "key.pem" || f == "rootCA-key.pem" || f == "bundle.p12") && runtime.GOOS != "windows" {
			if info.Mode().Perm() != 0600 {
				t.Errorf("File %s permissions should be 0600, got %o", f, info.Mode().Perm())
			}
		}
		if !found {
			t.Errorf("Expected SAN DNS %q not found in %v", exp, parsedCert.DNSNames)
		}
	}

	// Serial Number (128-bit)
	if parsedCert.SerialNumber == nil || parsedCert.SerialNumber.Sign() <= 0 {
		t.Fatalf("Serial number must be a positive integer")
	// 6. Verify PKCS#12 bundle contains both Leaf and CA cert
	p12PrivKey, p12Cert, caList, err := pkcs12.DecodeChain(res.PKCS12Bundle, "secret123")
	if err != nil {
		t.Fatalf("pkcs12.DecodeChain failed: %v", err)
	}
	max128Bit := new(big.Int).Lsh(big.NewInt(1), 128)
	if parsedCert.SerialNumber.Cmp(max128Bit) >= 0 {
		t.Errorf("Serial number %s exceeds 128 bits", parsedCert.SerialNumber.String())
	if p12Cert.Subject.CommonName != "app.internal" {
		t.Errorf("P12 cert CommonName mismatch: %s", p12Cert.Subject.CommonName)
	}

	// SKID and AKID
	if len(parsedCert.SubjectKeyId) == 0 {
		t.Errorf("SubjectKeyId must not be empty")
	if len(caList) == 0 || caList[0].Subject.CommonName != "Internal Enterprise Root CA" {
		t.Errorf("P12 CA chain missing Root CA: %v", caList)
	}
	if !bytes.Equal(parsedCert.SubjectKeyId, parsedCert.AuthorityKeyId) {
		t.Errorf("For self-signed cert, AKID must match SKID")
	if _, ok := p12PrivKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("P12 private key is not ECDSA")
	}

	// Validity dates
	skewTolerance := 10 * time.Minute
	if time.Since(parsedCert.NotBefore) > skewTolerance {
		t.Errorf("NotBefore skew too large: %v", parsedCert.NotBefore)
	}
	expectedNotAfter := parsedCert.NotBefore.Add(30 * 24 * time.Hour)
	if parsedCert.NotAfter.Sub(expectedNotAfter).Abs() > time.Minute {
		t.Errorf("NotAfter duration mismatch: got %v, expected %v", parsedCert.NotAfter, expectedNotAfter)
	}

	// Key verification
	ecKey, ok := res.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Private key is not *ecdsa.PrivateKey")
	}
	if ecKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", ecKey.Curve.Params().Name)
	}

	// PEM Verification & Unencrypted check
	block, rest := pem.Decode(res.PrivateKeyPEM)
	if block == nil || len(rest) > 0 {
		t.Fatalf("Failed to decode private key PEM cleanly")
	}
	if block.Type != "PRIVATE KEY" {
		t.Errorf("Expected PKCS#8 'PRIVATE KEY' PEM header, got %q", block.Type)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse unencrypted PKCS#8 private key: %v", err)
	}
	if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Parsed PKCS#8 key is not *ecdsa.PrivateKey")
	}

	// TLS KeyPair test
	// 7. Verify TLS key pair loads
	tlsCert, err := tls.X509KeyPair(res.CertificatePEM, res.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair failed: %v", err)
	}
	if len(tlsCert.Certificate) == 0 {
		t.Errorf("tls.Certificate slice is empty")
		t.Errorf("tls.Certificate is empty")
	}

	// PKCS#12 decoding test
	p12PrivKey, p12Cert, err := pkcs12.Decode(res.PKCS12Bundle, "secret123")
	if err != nil {
		t.Fatalf("pkcs12.Decode failed: %v", err)
	}
	if p12Cert.Subject.CommonName != "app.internal" {
		t.Errorf("PKCS#12 cert CN mismatch: %s", p12Cert.Subject.CommonName)
	}
	if _, ok := p12PrivKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("PKCS#12 private key mismatch")
	}

	// File existence and permissions
	if _, err := os.Stat(res.CertPath); err != nil {
		t.Errorf("Cert file not found at %s", res.CertPath)
	}
	keyInfo, err := os.Stat(res.KeyPath)
	if err != nil {
		t.Errorf("Key file not found at %s", res.KeyPath)
	} else if runtime.GOOS != "windows" {
		perm := keyInfo.Mode().Perm()
		if perm != 0600 {
			t.Errorf("Key file permissions should be 0600, got %o", perm)
		}
	}
}

func TestGenerateCAWithRSA4096(t *testing.T) {
func TestGenerateStandaloneCA(t *testing.T) {
	tempDir := t.TempDir()

	cfg := Config{
		Role:         RoleCA,
		KeyType:      KeyTypeRSA4096,
		CommonName:   "Internal Root CA",
		CommonName:   "Standalone Root CA",
		Organization: "Internal Infrastructure",
		Country:      "IN",
		ValidityDays: 1825, // 5 years
		ValidityDays: 1825,
		OutputDir:    tempDir,
		CertFileName: "ca.crt",
		KeyFileName:  "ca.key",
		KeyFormat:    "traditional", // Test traditional RSA PRIVATE KEY format
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

	// Basic Constraints
	if !parsedCert.IsCA {
		t.Errorf("CA certificate must have IsCA = true")
	}
	if parsedCert.MaxPathLen != 1 {
		t.Errorf("Expected MaxPathLen = 1, got %d", parsedCert.MaxPathLen)
	}
	if parsedCert.MaxPathLenZero {
		t.Errorf("MaxPathLenZero must be false for CA")
	}

	// Key Usages
	expectedUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if parsedCert.KeyUsage&expectedUsage != expectedUsage {
		t.Errorf("KeyUsage missing required flags: got %v, expected %v", parsedCert.KeyUsage, expectedUsage)
		t.Errorf("KeyUsage missing flags: %v", parsedCert.KeyUsage)
	}

	// RSA Key verification
	rsaKey, ok := res.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Private key is not *rsa.PrivateKey")
	if !ok || rsaKey.N.BitLen() != 4096 {
		t.Fatalf("Expected 4096-bit RSA key")
	}
	if rsaKey.N.BitLen() != 4096 {
		t.Errorf("Expected 4096-bit RSA key, got %d", rsaKey.N.BitLen())
	}

	// Traditional PEM header
	block, _ := pem.Decode(res.PrivateKeyPEM)
	if block == nil {
		t.Fatalf("Failed to decode traditional PEM block")
	}
	if block.Type != "RSA PRIVATE KEY" {
		t.Errorf("Expected 'RSA PRIVATE KEY', got %q", block.Type)
	}
	parsedRSA, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#1 RSA private key: %v", err)
	}
	if parsedRSA.N.BitLen() != 4096 {
		t.Errorf("Parsed RSA bit length mismatch")
	}

	// Self-signature verification
	if err := parsedCert.CheckSignatureFrom(parsedCert); err != nil {
		t.Errorf("CA self-signature verification failed: %v", err)
	}
}

func TestGenerateECDSA384AndRSA2048(t *testing.T) {
func TestGenerateStandaloneLeaf(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Test ECDSA P-384
	cfgP384 := Config{
	cfg := Config{
		Role:         RoleLeaf,
		KeyType:      KeyTypeECDSAP384,
		CommonName:   "p384.internal",
		OutputDir:    tempDir,
		CertFileName: "p384.pem",
		KeyFileName:  "p384.key",
	}
	resP384, err := Generate(cfgP384)
	res, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate P-384 failed: %v", err)
	}
	certP384, err := x509.ParseCertificate(resP384.CertificateDER)
	certP384, err := x509.ParseCertificate(res.CertificateDER)
	if err != nil {
		t.Fatalf("Parse P-384 failed: %v", err)
	}
	if err := certP384.CheckSignature(certP384.SignatureAlgorithm, certP384.RawTBSCertificate, certP384.Signature); err != nil {
		t.Errorf("P-384 cryptographic signature verification failed: %v", err)
		t.Errorf("P-384 signature verification failed: %v", err)
	}
	ecKey := resP384.PrivateKey.(*ecdsa.PrivateKey)
	if ecKey.Curve.Params().Name != "P-384" {
		t.Errorf("Expected P-384, got %s", ecKey.Curve.Params().Name)
	}

	// 2. Test RSA 2048
	cfgRSA2048 := Config{
		Role:         RoleLeaf,
		KeyType:      KeyTypeRSA2048,
		CommonName:   "rsa2048.internal",
		OutputDir:    tempDir,
		CertFileName: "rsa.pem",
		KeyFileName:  "rsa.key",
	}
	resRSA, err := Generate(cfgRSA2048)
	if err != nil {
		t.Fatalf("Generate RSA-2048 failed: %v", err)
	}
	certRSA, err := x509.ParseCertificate(resRSA.CertificateDER)
	if err != nil {
		t.Fatalf("Parse RSA-2048 failed: %v", err)
	}
	if err := certRSA.CheckSignature(certRSA.SignatureAlgorithm, certRSA.RawTBSCertificate, certRSA.Signature); err != nil {
		t.Errorf("RSA-2048 cryptographic signature verification failed: %v", err)
	}
	rsaKey := resRSA.PrivateKey.(*rsa.PrivateKey)
	if rsaKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048 bits, got %d", rsaKey.N.BitLen())
	}
}

func TestValidationErrors(t *testing.T) {
	tempDir := t.TempDir()

	// Empty CN
	cfg := Config{
		CommonName: "",
		OutputDir:  tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for empty CN, got nil")
	}

	// Invalid Country
	cfg = Config{
		CommonName: "test.local",
		Country:    "USA", // 3 letters
		Country:    "USA",
		OutputDir:  tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for 3-letter Country code, got nil")
	}

	// Validity duration too large
	cfg = Config{
		CommonName:   "test.local",
		ValidityDays: 4000,
		OutputDir:    tempDir,
	}
	if _, err := Generate(cfg); err == nil {
		t.Errorf("Expected error for validity > 3650 days, got nil")
	}
}

func TestFormatSummary(t *testing.T) {
	tempDir := t.TempDir()
	cfg := Config{
		Role:         RoleLeaf,
		KeyType:      KeyTypeECDSAP256,
		CommonName:   "summary.test",
		Organization: "Test Org",
		Country:      "US",
		ValidityDays: 90,
		OutputDir:    tempDir,
	}
	res, err := Generate(cfg)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	summary := res.FormatSummary()
	if !bytes.Contains([]byte(summary), []byte("summary.test")) {
		t.Errorf("Summary missing CN")
	}
	if !bytes.Contains([]byte(summary), []byte("Test Org")) {
		t.Errorf("Summary missing Organization")
	}
	if !bytes.Contains([]byte(summary), []byte("SHA-256 Fingerprint")) {
		t.Errorf("Summary missing Fingerprint")
	}
}
