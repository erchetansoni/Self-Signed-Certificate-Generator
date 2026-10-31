package cert

import (
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
type CertRole string

const (
	RoleCA   CertRole = "ca"
	RoleLeaf CertRole = "leaf"
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
}

// Result contains the generated cryptographic artifacts and metadata.
type Result struct {
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
func (c *Config) Validate() error {
	c.CommonName = strings.TrimSpace(c.CommonName)
	if c.CommonName == "" {
		return errors.New("common name (CN) cannot be empty")
	}

	if c.Role == "" {
		c.Role = RoleLeaf
	}
	if c.Role != RoleCA && c.Role != RoleLeaf {
		return fmt.Errorf("invalid certificate role %q (must be %q or %q)", c.Role, RoleCA, RoleLeaf)
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
	if c.GeneratePKCS12 && c.PKCS12FileName == "" {
		c.PKCS12FileName = "cert.p12"
	}

	if c.KeyFormat == "" {
		c.KeyFormat = "pkcs8"
	}

	// For Leaf certificates, ensure the CN is included in SANs if not already present
	if c.Role == RoleLeaf {
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
func Generate(cfg Config) (*Result, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation error: %w", err)
	}

	// 1. Generate Private Key
	privKey, pubKey, isRSA, err := generateKeyPair(cfg.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// 2. Generate 128-bit Cryptographically Secure Random Serial Number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random serial number: %w", err)
	}

	// 3. Compute Subject Key Identifier (RFC 5280 4.2.1.2)
	pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
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
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
		template.DNSNames = cfg.DNSNames
		template.IPAddresses = cfg.IPAddresses
	}

	// 7. Create Self-Signed Certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// 8. Encode Certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// 9. Encode Private Key to PEM
	keyPEM, err := encodePrivateKey(privKey, cfg.KeyFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	// 10. Generate Optional PKCS#12 Bundle
	var pfxData []byte
	if cfg.GeneratePKCS12 {
		pfxData, err = pkcs12.Encode(rand.Reader, privKey, parsedCert, nil, cfg.PKCS12Password)
		if err != nil {
			return nil, fmt.Errorf("failed to generate PKCS#12 bundle: %w", err)
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
		SerialNumberHex:   fmt.Sprintf("%032X", serialNumber),
	}

	// 12. Write Output Files
	if err := result.SaveFiles(cfg); err != nil {
		return nil, fmt.Errorf("failed to save output files: %w", err)
	}

	return result, nil
}

// SaveFiles writes the PEM and PKCS#12 files to disk with strict POSIX permissions.
func (r *Result) SaveFiles(cfg Config) error {
	outDir := filepath.Clean(cfg.OutputDir)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("unable to create output directory %q: %w", outDir, err)
	}

	// Write Certificate PEM (0644 readable by all)
	certPath := filepath.Join(outDir, cfg.CertFileName)
	if err := os.WriteFile(certPath, r.CertificatePEM, 0644); err != nil {
		return fmt.Errorf("unable to write certificate to %q: %w", certPath, err)
	}
	r.CertPath = certPath

	// Write Private Key PEM with strict 0600 permissions
	keyPath := filepath.Join(outDir, cfg.KeyFileName)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create private key file %q: %w", keyPath, err)
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
	if cfg.GeneratePKCS12 && len(r.PKCS12Bundle) > 0 {
		p12Path := filepath.Join(outDir, cfg.PKCS12FileName)
		p12File, err := os.OpenFile(p12Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("unable to create PKCS#12 file %q: %w", p12Path, err)
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
}

// HexFingerprint helper
func HexFingerprint(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}
