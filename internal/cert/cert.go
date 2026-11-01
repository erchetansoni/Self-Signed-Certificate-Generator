// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CertRole specifies the architecture / role of the generated certificates.
type CertRole string

const (
	RoleCALeaf     CertRole = "ca-leaf"     // Generate new Root CA & signed Leaf cert (Default)
	RoleExistingCA CertRole = "existing-ca" // Sign Leaf cert using an existing Root CA
	RoleCA         CertRole = "ca"          // Root / Intermediate CA only
	RoleLeaf       CertRole = "leaf"        // Standalone self-signed leaf without CA
)

// KeyType specifies the cryptographic algorithm and key size.
type KeyType string

const (
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	KeyTypeRSA2048   KeyType = "rsa-2048"
	KeyTypeRSA4096   KeyType = "rsa-4096"
)

// Config holds all parameters required to generate certificates and keys.
type Config struct {
	Role               CertRole
	KeyType            KeyType
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	DNSNames           []string
	IPAddresses        []net.IP
	ValidityDays       int

	// Root CA generation settings (used when Role == RoleCALeaf or RoleCA)
	RootCACommonName   string
	RootCAValidityDays int

	// Existing Root CA settings (used when Role == RoleExistingCA)
	ExistingCACertPath string
	ExistingCAKeyPath  string
	ExistingCAPassword string

	// Output file options
	OutputDir       string
	CertFileName    string
	KeyFileName     string
	RootCAFileName  string
	RootKeyFileName string
	ChainFileName   string
	GeneratePKCS12  bool
	PKCS12FileName  string
	PKCS12Password  string
	KeyFormat       string // "pkcs8" (default) or "traditional"
}

// Result contains the generated cryptographic artifacts and metadata.
type Result struct {
	// Leaf / Primary Certificate
	CertificateDER    []byte
	CertificatePEM    []byte
	PrivateKeyPEM     []byte
	Certificate       *x509.Certificate
	PrivateKey        any
	CertPath          string
	KeyPath           string
	FingerprintSHA256 string
	SerialNumberHex   string

	// Root CA (when Role == RoleCALeaf, RoleCA, or RoleExistingCA)
	IsPKI             bool
	IsExistingCA      bool
	RootCADER         []byte
	RootCAPEM         []byte
	RootCAKeyPEM      []byte
	RootCACertificate *x509.Certificate
	RootCAPath        string
	RootCAKeyPath     string
	RootCAFingerprint string
	RootCASerialHex   string

	// Certificate Chain & Bundles
	ChainPEM     []byte
	ChainPath    string
	PKCS12Bundle []byte
	PKCS12Path   string
}

// ExistingCAInfo holds metadata about an auto-detected or loaded Root CA.
type ExistingCAInfo struct {
	CertPath   string
	KeyPath    string
	CommonName string
	ExpiresAt  time.Time
}

// DetectExistingCA scans current working directory, executable directory, and subdirectories
// for matching Root CA certificate and key files.
func DetectExistingCA() *ExistingCAInfo {
	searchDirs := []string{"."}

	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		if exeDir != "." {
			searchDirs = append(searchDirs, exeDir)
		}
	}
	searchDirs = append(searchDirs, "./certs", "./dist")

	candidatePairs := [][2]string{
		{"rootCA.pem", "rootCA-key.pem"},
		{"rootCA.crt", "rootCA.key"},
		{"rootCA.crt", "rootCA-key.pem"},
		{"ca.pem", "ca-key.pem"},
		{"ca.crt", "ca.key"},
		{"ca.pem", "ca.key"},
	}

	for _, dir := range searchDirs {
		for _, pair := range candidatePairs {
			certPath := filepath.Join(dir, pair[0])
			keyPath := filepath.Join(dir, pair[1])

			if fileExists(certPath) && fileExists(keyPath) {
				// Verify certificate
				certData, err := os.ReadFile(certPath)
				if err != nil {
					continue
				}
				block, _ := pem.Decode(certData)
				if block == nil {
					continue
				}
				parsedCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil || !parsedCert.IsCA {
					continue
				}

				return &ExistingCAInfo{
					CertPath:   certPath,
					KeyPath:    keyPath,
					CommonName: parsedCert.Subject.CommonName,
					ExpiresAt:  parsedCert.NotAfter,
				}
			}
		}
	}
	return nil
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// LoadExistingCA reads and parses the Root CA certificate and private key from disk,
// validating that the certificate is a CA and the private key matches the certificate.
func LoadExistingCA(certPath, keyPath, password string) (*x509.Certificate, any, []byte, error) {
	if !fileExists(certPath) {
		return nil, nil, nil, fmt.Errorf("root CA certificate file not found at %q", certPath)
	}
	if !fileExists(keyPath) {
		return nil, nil, nil, fmt.Errorf("root CA private key file not found at %q", keyPath)
	}

	// 1. Read & parse Root CA certificate
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read Root CA certificate: %w", err)
	}
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("no PEM data found in Root CA certificate %q", certPath)
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse Root CA certificate: %w", err)
	}

	if !caCert.IsCA {
		return nil, nil, nil, fmt.Errorf("certificate in %q is not marked as a Certificate Authority (IsCA=false)", certPath)
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, nil, fmt.Errorf("certificate in %q lacks CertSign key usage permission", certPath)
	}

	// 2. Read & parse Root CA private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read Root CA private key: %w", err)
	}
	caPrivKey, err := parsePrivateKeyPEM(keyData, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse Root CA private key from %q: %w", keyPath, err)
	}

	// 3. Cryptographic consistency check: key matches cert
	if err := verifyKeyMatchesCert(caCert, caPrivKey); err != nil {
		return nil, nil, nil, err
	}

	return caCert, caPrivKey, certData, nil
}

func parsePrivateKeyPEM(keyBytes []byte, password string) (any, error) {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("no PEM block found in private key file")
	}

	der := block.Bytes
	// Handle encrypted PEM if legacy encryption
	if x509.IsEncryptedPEMBlock(block) {
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key with provided password: %w", err)
		}
	}

	// Try PKCS#8
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	// Try RSA PKCS#1
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	// Try EC SEC1
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported private key format: must be unencrypted PKCS#8, PKCS#1 (RSA), or SEC1 (EC)")
}

func verifyKeyMatchesCert(cert *x509.Certificate, priv any) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		privRSA, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return errors.New("certificate contains an RSA public key, but the provided private key is not RSA")
		}
		if pub.N.Cmp(privRSA.N) != 0 || pub.E != privRSA.E {
			return errors.New("private key does not match public key in the provided CA certificate")
		}
	case *ecdsa.PublicKey:
		privEC, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return errors.New("certificate contains an ECDSA public key, but the provided private key is not ECDSA")
		}
		if pub.X.Cmp(privEC.X) != 0 || pub.Y.Cmp(privEC.Y) != 0 {
			return errors.New("private key does not match public key in the provided CA certificate")
		}
	default:
		return fmt.Errorf("unsupported public key algorithm in CA certificate: %T", cert.PublicKey)
	}
	return nil
}

// ParseSANLists takes comma-separated strings for DNS names and IP addresses
// and parses them into typed slices with whitespace trimming and validation.
func ParseSANLists(dnsInput, ipInput string) ([]string, []net.IP, error) {
	var dnsNames []string
	var ipAddresses []net.IP

	if strings.TrimSpace(dnsInput) != "" {
		for _, raw := range strings.Split(dnsInput, ",") {
			item := strings.TrimSpace(raw)
			if item == "" {
				continue
			}
			if ip := net.ParseIP(item); ip != nil {
				ipAddresses = append(ipAddresses, ip)
			} else {
				dnsNames = append(dnsNames, item)
			}
		}
	}

	if strings.TrimSpace(ipInput) != "" {
		for _, raw := range strings.Split(ipInput, ",") {
			item := strings.TrimSpace(raw)
			if item == "" {
				continue
			}
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, nil, fmt.Errorf("invalid IP address in SAN list: %q", item)
			}
			ipAddresses = append(ipAddresses, ip)
		}
	}

	return dnsNames, ipAddresses, nil
}

// Validate verifies configuration fields and applies sensible defaults.
func (c *Config) Validate() error {
	c.CommonName = strings.TrimSpace(c.CommonName)
	if c.CommonName == "" {
		return errors.New("common name (CN) cannot be empty")
	}

	if c.Role == "" {
		c.Role = RoleCALeaf
	}
	switch c.Role {
	case RoleCALeaf, RoleExistingCA, RoleCA, RoleLeaf:
		// Valid
	default:
		return fmt.Errorf("invalid certificate role %q (must be %q, %q, %q, or %q)", c.Role, RoleCALeaf, RoleExistingCA, RoleCA, RoleLeaf)
	}

	if c.Role == RoleExistingCA {
		if strings.TrimSpace(c.ExistingCACertPath) == "" {
			return errors.New("existing CA certificate path (-ca-cert) cannot be empty when using existing-ca role")
		}
		if strings.TrimSpace(c.ExistingCAKeyPath) == "" {
			return errors.New("existing CA private key path (-ca-key) cannot be empty when using existing-ca role")
		}
	}

	if c.KeyType == "" {
		c.KeyType = KeyTypeECDSAP256
	}
	switch c.KeyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048, KeyTypeRSA4096:
		// Valid
	default:
		return fmt.Errorf("unsupported key type: %q", c.KeyType)
	}

	if c.ValidityDays <= 0 {
		c.ValidityDays = 365
	}
	if c.ValidityDays > 3650 {
		return errors.New("validity duration exceeds maximum allowed of 3650 days (10 years)")
	}

	if c.RootCAValidityDays <= 0 {
		c.RootCAValidityDays = 3650
	}

	if c.RootCACommonName == "" {
		if c.Role == RoleCA {
			c.RootCACommonName = c.CommonName
		} else {
			c.RootCACommonName = fmt.Sprintf("%s Root CA", c.CommonName)
		}
	}

	c.Country = strings.ToUpper(strings.TrimSpace(c.Country))
	if c.Country != "" && len(c.Country) != 2 {
		return fmt.Errorf("country code must be a 2-letter ISO 3166-1 code, got %q", c.Country)
	}

	if c.Organization == "" {
		c.Organization = "Internal / Dev"
	}

	if c.OutputDir == "" {
		c.OutputDir = "."
	}
	if c.CertFileName == "" {
		c.CertFileName = "cert.pem"
	}
	if c.KeyFileName == "" {
		c.KeyFileName = "key.pem"
	}
	if c.RootCAFileName == "" {
		c.RootCAFileName = "rootCA.pem"
	}
	if c.RootKeyFileName == "" {
		c.RootKeyFileName = "rootCA-key.pem"
	}
	if c.ChainFileName == "" {
		c.ChainFileName = "chain.pem"
	}
	if c.GeneratePKCS12 && c.PKCS12FileName == "" {
		c.PKCS12FileName = "bundle.p12"
	}
	if c.KeyFormat == "" {
		c.KeyFormat = "pkcs8"
	}

	// For Leaf certificates, ensure the CN is included in SANs if not already present
	if c.Role == RoleLeaf || c.Role == RoleCALeaf || c.Role == RoleExistingCA {
		if ip := net.ParseIP(c.CommonName); ip != nil {
			found := false
			for _, existingIP := range c.IPAddresses {
				if existingIP.Equal(ip) {
					found = true
					break
				}
			}
			if !found {
				c.IPAddresses = append(c.IPAddresses, ip)
			}
		} else {
			found := false
			for _, existingDNS := range c.DNSNames {
				if strings.EqualFold(existingDNS, c.CommonName) {
					found = true
					break
				}
			}
			if !found {
				c.DNSNames = append(c.DNSNames, c.CommonName)
			}
		}
	}

	return nil
}

// Generate creates the certificate(s) and private key(s) based on configuration.
func Generate(cfg Config) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	switch cfg.Role {
	case RoleCALeaf:
		return generatePKIHierarchy(cfg)
	case RoleExistingCA:
		return generateSignedByExistingCA(cfg)
	case RoleCA:
		return generateStandaloneCA(cfg)
	default:
		return generateStandaloneLeaf(cfg)
	}
}

// generateSignedByExistingCA loads an existing Root CA from disk and issues a signed leaf certificate.
func generateSignedByExistingCA(cfg Config) (*Result, error) {
	caCert, caPrivKey, caCertPEM, err := LoadExistingCA(cfg.ExistingCACertPath, cfg.ExistingCAKeyPath, cfg.ExistingCAPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to load existing Root CA: %w", err)
	}

	// 1. Generate Leaf Key Pair
	leafPrivKey, leafPubKey, leafIsRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Leaf key pair: %w", err)
	}

	// 2. Generate 128-bit Serial Number for Leaf
	leafSerial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	// 3. Compute Leaf SKID
	leafPubDER, err := x509.MarshalPKIXPublicKey(leafPubKey)
	if err != nil {
		return nil, err
	}
	leafSKID := computeSKID(leafPubDER)

	// 4. Build Leaf Template
	leafSubject := pkix.Name{
		CommonName: cfg.CommonName,
	}
	if cfg.Organization != "" {
		leafSubject.Organization = []string{cfg.Organization}
	}
	if cfg.OrganizationalUnit != "" {
		leafSubject.OrganizationalUnit = []string{cfg.OrganizationalUnit}
	}
	if cfg.Country != "" {
		leafSubject.Country = []string{cfg.Country}
	}

	leafNotBefore := time.Now().UTC().Add(-5 * time.Minute)
	leafNotAfter := leafNotBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)

	// Check if leaf validity exceeds CA expiration
	if leafNotAfter.After(caCert.NotAfter) {
		leafNotAfter = caCert.NotAfter
	}

	leafAKID := caCert.SubjectKeyId
	if len(leafAKID) == 0 {
		caPubDER, _ := x509.MarshalPKIXPublicKey(caCert.PublicKey)
		leafAKID = computeSKID(caPubDER)
	}

	leafTemplate := x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               leafSubject,
		NotBefore:             leafNotBefore,
		NotAfter:              leafNotAfter,
		SubjectKeyId:          leafSKID,
		AuthorityKeyId:        leafAKID,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPAddresses,
	}
	if leafIsRSA {
		leafTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// 5. Sign Leaf Certificate using the Existing Root CA
	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, leafPubKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign Leaf certificate with existing Root CA: %w", err)
	}
	parsedLeafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed Leaf certificate: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	leafKeyPEM, err := encodePrivateKey(leafPrivKey, cfg.KeyFormat)
	if err != nil {
		return nil, err
	}

	// 6. Concatenate Full Chain (Leaf + Existing CA)
	chainPEM := bytes.Join([][]byte{leafCertPEM, caCertPEM}, []byte(""))

	// 7. Generate Optional PKCS#12 Bundle containing Leaf + Existing CA
	var pfxData []byte
	if cfg.GeneratePKCS12 {
		pfxData, err = pkcs12.Encode(rand.Reader, leafPrivKey, parsedLeafCert, []*x509.Certificate{caCert}, cfg.PKCS12Password)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCS#12 bundle: %w", err)
		}
	}

	result := &Result{
		CertificateDER:    leafCertDER,
		CertificatePEM:    leafCertPEM,
		PrivateKeyPEM:     leafKeyPEM,
		Certificate:       parsedLeafCert,
		PrivateKey:        leafPrivKey,
		FingerprintSHA256: formatFingerprint(leafCertDER),
		SerialNumberHex:   fmt.Sprintf("%032X", leafSerial),

		IsPKI:             true,
		IsExistingCA:      true,
		RootCADER:         caCert.Raw,
		RootCAPEM:         caCertPEM,
		RootCACertificate: caCert,
		RootCAPath:        cfg.ExistingCACertPath,
		RootCAKeyPath:     cfg.ExistingCAKeyPath,
		RootCAFingerprint: formatFingerprint(caCert.Raw),
		RootCASerialHex:   fmt.Sprintf("%032X", caCert.SerialNumber),

		ChainPEM:     chainPEM,
		PKCS12Bundle: pfxData,
	}

	if err := result.SaveFiles(cfg); err != nil {
		return nil, fmt.Errorf("failed to save output files: %w", err)
	}

	return result, nil
}

// generatePKIHierarchy generates a dedicated Root CA and issues a Leaf Certificate signed by it.
func generatePKIHierarchy(cfg Config) (*Result, error) {
	// 1. Generate Root CA Key Pair
	caPrivKey, caPubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key pair: %w", err)
	}

	// 2. Generate 128-bit Serial Number for Root CA
	caSerial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	// 3. Compute Root CA SKID
	caPubDER, err := x509.MarshalPKIXPublicKey(caPubKey)
	if err != nil {
		return nil, err
	}
	caSKID := computeSKID(caPubDER)

	// 4. Build Root CA Template
	caSubject := pkix.Name{
		CommonName: cfg.RootCACommonName,
	}
	if cfg.Organization != "" {
		caSubject.Organization = []string{cfg.Organization}
	}
	if cfg.Country != "" {
		caSubject.Country = []string{cfg.Country}
	}

	caNotBefore := time.Now().UTC().Add(-5 * time.Minute)
	caNotAfter := caNotBefore.Add(time.Duration(cfg.RootCAValidityDays) * 24 * time.Hour)

	caTemplate := x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               caSubject,
		NotBefore:             caNotBefore,
		NotAfter:              caNotAfter,
		SubjectKeyId:          caSKID,
		AuthorityKeyId:        caSKID,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	if isRSA {
		caTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// 5. Self-Sign Root CA
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, caPubKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to self-sign Root CA: %w", err)
	}
	parsedCACert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Root CA: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	caKeyPEM, err := encodePrivateKey(caPrivKey, cfg.KeyFormat)
	if err != nil {
		return nil, err
	}

	// 6. Generate Leaf Key Pair
	leafPrivKey, leafPubKey, leafIsRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Leaf key pair: %w", err)
	}

	leafSerial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}

	leafPubDER, err := x509.MarshalPKIXPublicKey(leafPubKey)
	if err != nil {
		return nil, err
	}
	leafSKID := computeSKID(leafPubDER)

	// 7. Build Leaf Template
	leafSubject := pkix.Name{
		CommonName: cfg.CommonName,
	}
	if cfg.Organization != "" {
		leafSubject.Organization = []string{cfg.Organization}
	}
	if cfg.OrganizationalUnit != "" {
		leafSubject.OrganizationalUnit = []string{cfg.OrganizationalUnit}
	}
	if cfg.Country != "" {
		leafSubject.Country = []string{cfg.Country}
	}

	leafNotBefore := time.Now().UTC().Add(-5 * time.Minute)
	leafNotAfter := leafNotBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)

	leafTemplate := x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               leafSubject,
		NotBefore:             leafNotBefore,
		NotAfter:              leafNotAfter,
		SubjectKeyId:          leafSKID,
		AuthorityKeyId:        caSKID, // Signed by CA!
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPAddresses,
	}
	if leafIsRSA {
		leafTemplate.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// 8. Sign Leaf Certificate with Root CA
	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, parsedCACert, leafPubKey, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign Leaf certificate with Root CA: %w", err)
	}
	parsedLeafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed Leaf certificate: %w", err)
	}

	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	leafKeyPEM, err := encodePrivateKey(leafPrivKey, cfg.KeyFormat)
	if err != nil {
		return nil, err
	}

	// 9. Concatenate Full Chain (Leaf + CA)
	chainPEM := bytes.Join([][]byte{leafCertPEM, caCertPEM}, []byte(""))

	// 10. Generate Optional PKCS#12 Bundle containing Leaf + CA
	var pfxData []byte
	if cfg.GeneratePKCS12 {
		pfxData, err = pkcs12.Encode(rand.Reader, leafPrivKey, parsedLeafCert, []*x509.Certificate{parsedCACert}, cfg.PKCS12Password)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCS#12 bundle: %w", err)
		}
	}

	result := &Result{
		CertificateDER:    leafCertDER,
		CertificatePEM:    leafCertPEM,
		PrivateKeyPEM:     leafKeyPEM,
		Certificate:       parsedLeafCert,
		PrivateKey:        leafPrivKey,
		FingerprintSHA256: formatFingerprint(leafCertDER),
		SerialNumberHex:   fmt.Sprintf("%032X", leafSerial),

		IsPKI:             true,
		IsExistingCA:      false,
		RootCADER:         caCertDER,
		RootCAPEM:         caCertPEM,
		RootCAKeyPEM:      caKeyPEM,
		RootCACertificate: parsedCACert,
		RootCAFingerprint: formatFingerprint(caCertDER),
		RootCASerialHex:   fmt.Sprintf("%032X", caSerial),

		ChainPEM:     chainPEM,
		PKCS12Bundle: pfxData,
	}

	if err := result.SaveFiles(cfg); err != nil {
		return nil, fmt.Errorf("failed to save output files: %w", err)
	}

	return result, nil
}

// generateStandaloneCA generates only a Root CA.
func generateStandaloneCA(cfg Config) (*Result, error) {
	caPrivKey, caPubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, err
	}
	caSerial, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(caPubKey)
	if err != nil {
		return nil, err
	}
	skid := computeSKID(pubDER)

	subject := pkix.Name{
		CommonName: cfg.CommonName,
	}
	if cfg.Organization != "" {
		subject.Organization = []string{cfg.Organization}
	}
	if cfg.Country != "" {
		subject.Country = []string{cfg.Country}
	}

	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		DNSNames:              cfg.DNSNames,
		IPAddresses:           cfg.IPAddresses,
	}
	if isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, caPubKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(caPrivKey, cfg.KeyFormat)
	if err != nil {
		return nil, err
	}

	result := &Result{
		CertificateDER:    certDER,
		CertificatePEM:    certPEM,
		PrivateKeyPEM:     keyPEM,
		Certificate:       parsedCert,
		PrivateKey:        caPrivKey,
		FingerprintSHA256: formatFingerprint(certDER),
		SerialNumberHex:   fmt.Sprintf("%032X", caSerial),

		IsPKI:             true,
		IsExistingCA:      false,
		RootCADER:         certDER,
		RootCAPEM:         certPEM,
		RootCAKeyPEM:      keyPEM,
		RootCACertificate: parsedCert,
		RootCAFingerprint: formatFingerprint(certDER),
		RootCASerialHex:   fmt.Sprintf("%032X", caSerial),
	}

	if err := result.SaveFiles(cfg); err != nil {
		return nil, err
	}
	return result, nil
}

// generateStandaloneLeaf generates a single self-signed leaf certificate without a CA.
func generateStandaloneLeaf(cfg Config) (*Result, error) {
	privKey, pubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, err
	}
	serialNumber, err := generateSerialNumber()
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	skid := computeSKID(pubDER)

	subject := pkix.Name{
		CommonName: cfg.CommonName,
	}
	if cfg.Organization != "" {
		subject.Organization = []string{cfg.Organization}
	}
	if cfg.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{cfg.OrganizationalUnit}
	}
	if cfg.Country != "" {
		subject.Country = []string{cfg.Country}
	}

	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid,
		IsCA:                  false,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPAddresses,
	}
	if isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, err
	}
	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(privKey, cfg.KeyFormat)
	if err != nil {
		return nil, err
	}

	var pfxData []byte
	if cfg.GeneratePKCS12 {
		pfxData, err = pkcs12.Encode(rand.Reader, privKey, parsedCert, nil, cfg.PKCS12Password)
		if err != nil {
			return nil, err
		}
	}

	result := &Result{
		CertificateDER:    certDER,
		CertificatePEM:    certPEM,
		PrivateKeyPEM:     keyPEM,
		Certificate:       parsedCert,
		PrivateKey:        privKey,
		FingerprintSHA256: formatFingerprint(certDER),
		SerialNumberHex:   fmt.Sprintf("%032X", serialNumber),
		PKCS12Bundle:      pfxData,
	}

	if err := result.SaveFiles(cfg); err != nil {
		return nil, err
	}
	return result, nil
}

// SaveFiles writes all generated artifacts to the output directory with strict permissions.
func (r *Result) SaveFiles(cfg Config) error {
	outDir := filepath.Clean(cfg.OutputDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("unable to create output directory %q: %w", outDir, err)
	}

	// 1. If Root CA was newly generated (RoleCALeaf or RoleCA), save Root CA files.
	// (If RoleExistingCA, we do NOT overwrite the existing CA files!)
	if r.IsPKI && !r.IsExistingCA && len(r.RootCAPEM) > 0 {
		rootCertPath := filepath.Join(outDir, cfg.RootCAFileName)
		if err := os.WriteFile(rootCertPath, r.RootCAPEM, 0644); err != nil {
			return fmt.Errorf("unable to write Root CA certificate to %q: %w", rootCertPath, err)
		}
		r.RootCAPath = rootCertPath

		rootKeyPath := filepath.Join(outDir, cfg.RootKeyFileName)
		if err := writePrivateKeyFile(rootKeyPath, r.RootCAKeyPEM); err != nil {
			return err
		}
		r.RootCAKeyPath = rootKeyPath
	}

	// If Role was CA only, we're done with files
	if cfg.Role == RoleCA {
		r.CertPath = r.RootCAPath
		r.KeyPath = r.RootCAKeyPath
		return nil
	}

	// 2. Write Leaf Certificate PEM
	certPath := filepath.Join(outDir, cfg.CertFileName)
	if err := os.WriteFile(certPath, r.CertificatePEM, 0644); err != nil {
		return fmt.Errorf("unable to write certificate to %q: %w", certPath, err)
	}
	r.CertPath = certPath

	// 3. Write Leaf Private Key PEM (strict 0600)
	keyPath := filepath.Join(outDir, cfg.KeyFileName)
	if err := writePrivateKeyFile(keyPath, r.PrivateKeyPEM); err != nil {
		return err
	}
	r.KeyPath = keyPath

	// 4. Write Full Chain PEM (if in PKI mode)
	if r.IsPKI && len(r.ChainPEM) > 0 {
		chainPath := filepath.Join(outDir, cfg.ChainFileName)
		if err := os.WriteFile(chainPath, r.ChainPEM, 0644); err != nil {
			return fmt.Errorf("unable to write certificate chain to %q: %w", chainPath, err)
		}
		r.ChainPath = chainPath
	}

	// 5. Write PKCS#12 bundle if generated
	if cfg.GeneratePKCS12 && len(r.PKCS12Bundle) > 0 {
		p12Path := filepath.Join(outDir, cfg.PKCS12FileName)
		if err := writePrivateKeyFile(p12Path, r.PKCS12Bundle); err != nil {
			return err
		}
		r.PKCS12Path = p12Path
	}

	return nil
}

func writePrivateKeyFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create private file %q: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return fmt.Errorf("unable to write private file data: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("unable to close private file: %w", err)
	}
	_ = os.Chmod(path, 0600)
	return nil
}

func generateSerialNumber() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func generateKeyPair(kt KeyType) (any, any, bool, error) {
	switch kt {
	case KeyTypeECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, false, err
		}
		return priv, &priv.PublicKey, false, nil

	case KeyTypeECDSAP384:
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, false, err
		}
		return priv, &priv.PublicKey, false, nil

	case KeyTypeRSA2048:
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, true, err
		}
		return priv, &priv.PublicKey, true, nil

	case KeyTypeRSA4096:
		priv, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, nil, true, err
		}
		return priv, &priv.PublicKey, true, nil

	default:
		return nil, nil, false, fmt.Errorf("unsupported key type %q", kt)
	}
}

func encodePrivateKey(priv any, format string) ([]byte, error) {
	if format == "traditional" {
		switch k := priv.(type) {
		case *rsa.PrivateKey:
			return pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(k),
			}), nil
		case *ecdsa.PrivateKey:
			der, err := x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, err
			}
			return pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: der,
			}), nil
		}
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

func computeSKID(pubDER []byte) []byte {
	type subjectPublicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(pubDER, &spki); err == nil {
		h := sha1.Sum(spki.PublicKey.Bytes)
		return h[:]
	}
	h := sha1.Sum(pubDER)
	return h[:]
}

func formatFingerprint(der []byte) string {
	fpRaw := sha256.Sum256(der)
	var fpParts []string
	for _, b := range fpRaw {
		fpParts = append(fpParts, fmt.Sprintf("%02X", b))
	}
	return strings.Join(fpParts, ":")
}

// HexFingerprint helper
func HexFingerprint(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}
