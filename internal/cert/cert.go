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

// CertRole specifies the intended role of the certificate.
// CertRole specifies the architecture / role of the generated certificates.
type CertRole string

const (
	RoleCA   CertRole = "ca"
	RoleLeaf CertRole = "leaf"
	RoleCALeaf CertRole = "ca-leaf" // Complete PKI: Generates Root CA & signed Leaf cert (Default)
	RoleCA     CertRole = "ca"      // Root / Intermediate CA only
	RoleLeaf   CertRole = "leaf"    // Standalone self-signed leaf without CA
)

// KeyType specifies the cryptographic algorithm and key size.
type KeyType string

const (
	KeyTypeECDSAP256 KeyType = "ecdsa-p256"
	KeyTypeECDSAP384 KeyType = "ecdsa-p384"
	KeyTypeRSA2048   KeyType = "rsa-2048"
	KeyTypeRSA4096   KeyType = "rsa-4096"
)

// Config holds all parameters required to generate the certificate and private key.
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
	OutputDir          string
	CertFileName       string
	KeyFileName        string
	GeneratePKCS12     bool
	PKCS12FileName     string
	PKCS12Password     string
	KeyFormat          string // "pkcs8" (default) or "traditional"

	// Root CA specific settings (used when Role == RoleCALeaf or RoleCA)
	RootCACommonName   string
	RootCAValidityDays int

	// Output file options
	OutputDir      string
	CertFileName   string
	KeyFileName    string
	RootCAFileName string
	RootKeyFileName string
	ChainFileName  string
	GeneratePKCS12 bool
	PKCS12FileName string
	PKCS12Password string
	KeyFormat      string // "pkcs8" (default) or "traditional"
}

// Result contains the generated cryptographic artifacts and metadata.
type Result struct {
	// Leaf / Primary Certificate
	CertificateDER    []byte
	CertificatePEM    []byte
	PrivateKeyPEM     []byte
	PKCS12Bundle      []byte
	Certificate       *x509.Certificate
	PrivateKey        any
	CertPath          string
	KeyPath           string
	PKCS12Path        string
	FingerprintSHA256 string
	SerialNumberHex   string

	// Root CA (when Role == RoleCALeaf or RoleCA)
	IsPKI             bool
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
			// If user accidentally put an IP in the DNS field, classify correctly
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

// Validate verifies the configuration fields and applies sensible defaults.
// Validate verifies configuration fields and applies sensible defaults.
func (c *Config) Validate() error {
	c.CommonName = strings.TrimSpace(c.CommonName)
	if c.CommonName == "" {
		return errors.New("common name (CN) cannot be empty")
	}

	if c.Role == "" {
		c.Role = RoleLeaf
		c.Role = RoleCALeaf
	}
	if c.Role != RoleCA && c.Role != RoleLeaf {
		return fmt.Errorf("invalid certificate role %q (must be %q or %q)", c.Role, RoleCA, RoleLeaf)
	switch c.Role {
	case RoleCALeaf, RoleCA, RoleLeaf:
		// Valid
	default:
		return fmt.Errorf("invalid certificate role %q (must be %q, %q, or %q)", c.Role, RoleCALeaf, RoleCA, RoleLeaf)
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
		c.RootCAValidityDays = 3650 // 10 years for Root CA
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
		c.PKCS12FileName = "cert.p12"
		c.PKCS12FileName = "bundle.p12"
	}

	if c.KeyFormat == "" {
		c.KeyFormat = "pkcs8"
	}

	// For Leaf certificates, ensure the CN is included in SANs if not already present
	if c.Role == RoleLeaf {
	if c.Role == RoleLeaf || c.Role == RoleCALeaf {
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

// Generate creates the self-signed X.509 certificate and private key.
// Generate creates the certificate(s) and private key(s) based on configuration.
func Generate(cfg Config) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// 1. Generate Private Key
	privKey, pubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	switch cfg.Role {
	case RoleCALeaf:
		return generatePKIHierarchy(cfg)
	case RoleCA:
		return generateStandaloneCA(cfg)
	default:
		return generateStandaloneLeaf(cfg)
	}
}

// generatePKIHierarchy generates a dedicated Root CA and issues a Leaf Certificate signed by it.
func generatePKIHierarchy(cfg Config) (*Result, error) {
	// 1. Generate Root CA Key Pair
	caPrivKey, caPubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
		return nil, fmt.Errorf("failed to generate CA key pair: %w", err)
	}

	// 2. Generate 128-bit Cryptographically Secure Random Serial Number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	// 2. Generate 128-bit Serial Number for Root CA
	caSerial, err := generateSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial number: %w", err)
		return nil, err
	}

	// 3. Compute Subject Key Identifier (RFC 5280 4.2.1.2)
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
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
		return nil, err
	}
	skid := computeSKID(pubDER)

	// 4. Construct Subject Distinguished Name
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

	// 5. Construct Validity Period (include 5-min backward skew tolerance)
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour)

	// 6. Build X.509 Certificate Template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          skid,
		AuthorityKeyId:        skid, // Self-signed
		AuthorityKeyId:        skid,
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	if cfg.Role == RoleCA {
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		if isRSA {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
		template.MaxPathLen = 1
		template.MaxPathLenZero = false
		// CA may also include SANs if provided
		template.DNSNames = cfg.DNSNames
		template.IPAddresses = cfg.IPAddresses
	} else {
		// Leaf certificate (Server & Client Auth)
		template.IsCA = false
		template.KeyUsage = x509.KeyUsageDigitalSignature
		if isRSA {
			template.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
		template.ExtKeyUsage = []x509.ExtKeyUsage{
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
		template.DNSNames = cfg.DNSNames
		template.IPAddresses = cfg.IPAddresses
		},
		DNSNames:    cfg.DNSNames,
		IPAddresses: cfg.IPAddresses,
	}
	if isRSA {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}

	// 7. Create Self-Signed Certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
		return nil, err
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
		return nil, err
	}

	// 8. Encode Certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// 9. Encode Private Key to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM, err := encodePrivateKey(privKey, cfg.KeyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
		return nil, err
	}

	// 10. Generate Optional PKCS#12 Bundle
	var pfxData []byte
	if cfg.GeneratePKCS12 {
		pfxData, err = pkcs12.Encode(rand.Reader, privKey, parsedCert, nil, cfg.PKCS12Password)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCS#12 bundle: %w", err)
			return nil, err
		}
	}

	// 11. Calculate SHA-256 Fingerprint
	fpRaw := sha256.Sum256(certDER)
	var fpParts []string
	for _, b := range fpRaw {
		fpParts = append(fpParts, fmt.Sprintf("%02X", b))
	}
	fingerprint := strings.Join(fpParts, ":")

	result := &Result{
		CertificateDER:    certDER,
		CertificatePEM:    certPEM,
		PrivateKeyPEM:     keyPEM,
		PKCS12Bundle:      pfxData,
		Certificate:       parsedCert,
		PrivateKey:        privKey,
		FingerprintSHA256: fingerprint,
		FingerprintSHA256: formatFingerprint(certDER),
		SerialNumberHex:   fmt.Sprintf("%032X", serialNumber),
		PKCS12Bundle:      pfxData,
	}

	// 12. Write Output Files
	if err := result.SaveFiles(cfg); err != nil {
		return nil, fmt.Errorf("failed to save output files: %w", err)
		return nil, err
	}

	return result, nil
}

// SaveFiles writes the PEM and PKCS#12 files to disk with strict POSIX permissions.
// SaveFiles writes all generated artifacts to the output directory with strict permissions.
func (r *Result) SaveFiles(cfg Config) error {
	outDir := filepath.Clean(cfg.OutputDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("unable to create output directory %q: %w", outDir, err)
	}

	// Write Certificate PEM (0644 readable by all)
	// 1. If Root CA was generated (RoleCALeaf or RoleCA), save Root CA files
	if r.IsPKI && len(r.RootCAPEM) > 0 {
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

	// Write Private Key PEM with strict 0600 permissions
	// 3. Write Leaf Private Key PEM (strict 0600)
	keyPath := filepath.Join(outDir, cfg.KeyFileName)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create private key file %q: %w", keyPath, err)
	if err := writePrivateKeyFile(keyPath, r.PrivateKeyPEM); err != nil {
		return err
	}
	if _, err := keyFile.Write(r.PrivateKeyPEM); err != nil {
		keyFile.Close()
		return fmt.Errorf("unable to write private key data to %q: %w", keyPath, err)
	}
	if err := keyFile.Close(); err != nil {
		return fmt.Errorf("unable to close private key file: %w", err)
	}
	// Enforce 0600 file permissions explicitly
	_ = os.Chmod(keyPath, 0600)
	r.KeyPath = keyPath

	// Write PKCS#12 bundle if generated with strict 0600 permissions
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
		p12File, err := os.OpenFile(p12Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("unable to create PKCS#12 file %q: %w", p12Path, err)
		if err := writePrivateKeyFile(p12Path, r.PKCS12Bundle); err != nil {
			return err
		}
		if _, err := p12File.Write(r.PKCS12Bundle); err != nil {
			p12File.Close()
			return fmt.Errorf("unable to write PKCS#12 data: %w", err)
		}
		if err := p12File.Close(); err != nil {
			return fmt.Errorf("unable to close PKCS#12 file: %w", err)
		}
		_ = os.Chmod(p12Path, 0600)
		r.PKCS12Path = p12Path
	}

	return nil
}

// generateKeyPair creates the private/public key pair based on the chosen key algorithm.
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

// encodePrivateKey serializes the private key to unencrypted PEM format.
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

	// Default to universal PKCS#8 format (RFC 5208 / RFC 5958)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}

// computeSKID calculates the Subject Key Identifier per RFC 5280 Section 4.2.1.2.
// It computes the 160-bit SHA-1 hash of the BIT STRING subjectPublicKey.
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
	// Fallback to hashing entire DER
	h := sha1.Sum(pubDER)
	return h[:]
}

// FormatSummary generates a clear, human-readable summary of the certificate details.
func (r *Result) FormatSummary() string {
	var sb strings.Builder
	c := r.Certificate

	sb.WriteString(fmt.Sprintf("  Common Name (CN): %s\n", c.Subject.CommonName))
	if len(c.Subject.Organization) > 0 {
		sb.WriteString(fmt.Sprintf("  Organization (O): %s\n", strings.Join(c.Subject.Organization, ", ")))
func formatFingerprint(der []byte) string {
	fpRaw := sha256.Sum256(der)
	var fpParts []string
	for _, b := range fpRaw {
		fpParts = append(fpParts, fmt.Sprintf("%02X", b))
	}
	if len(c.Subject.OrganizationalUnit) > 0 {
		sb.WriteString(fmt.Sprintf("  Organizational Unit (OU): %s\n", strings.Join(c.Subject.OrganizationalUnit, ", ")))
	}
	if len(c.Subject.Country) > 0 {
		sb.WriteString(fmt.Sprintf("  Country (C): %s\n", strings.Join(c.Subject.Country, ", ")))
	}

	roleStr := "Leaf (Server & Client Auth)"
	if c.IsCA {
		roleStr = "Certificate Authority (CA)"
	}
	sb.WriteString(fmt.Sprintf("  Role: %s\n", roleStr))
	sb.WriteString(fmt.Sprintf("  Serial Number: %s\n", r.SerialNumberHex))
	sb.WriteString(fmt.Sprintf("  Validity: %s to %s\n", c.NotBefore.Format("2006-01-02 15:04:05 UTC"), c.NotAfter.Format("2006-01-02 15:04:05 UTC")))

	if len(c.DNSNames) > 0 {
		sb.WriteString(fmt.Sprintf("  SAN DNS: %s\n", strings.Join(c.DNSNames, ", ")))
	}
	if len(c.IPAddresses) > 0 {
		var ips []string
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		sb.WriteString(fmt.Sprintf("  SAN IP: %s\n", strings.Join(ips, ", ")))
	}

	sb.WriteString(fmt.Sprintf("  SHA-256 Fingerprint: %s\n", r.FingerprintSHA256))
	sb.WriteString(fmt.Sprintf("  Certificate File: %s\n", r.CertPath))
	sb.WriteString(fmt.Sprintf("  Private Key File: %s\n", r.KeyPath))
	if r.PKCS12Path != "" {
		sb.WriteString(fmt.Sprintf("  PKCS#12 Bundle: %s\n", r.PKCS12Path))
	}

	return sb.String()
	return strings.Join(fpParts, ":")
}

// HexFingerprint helper
func HexFingerprint(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}
