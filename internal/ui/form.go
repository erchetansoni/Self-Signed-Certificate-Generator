package ui

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"certgen/internal/cert"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// FormData holds the interactive user choices from the TUI form.
type FormData struct {
	Role         string
	KeyType      string
	CommonName   string
	Organization string
	Unit         string
	Country      string
	SANDNS       string
	SANIP        string
	ValidityDays string
	OutputDir    string
	NamingScheme string
	GenPKCS12    bool
	P12Password  string
}

// Banner returns the styled application header.
func Banner() string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 2).
		MarginBottom(1)

	subTitleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7D56F4")).
		Italic(true)

	secBadge := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575")).
		Bold(true).
		SetString("[EDR-Safe / Air-Gapped / Zero-Network]")

	header := fmt.Sprintf("%s  %s\n%s\n",
		titleStyle.Render("CERTGEN"),
		secBadge.Render(),
		subTitleStyle.Render("Production-Grade Self-Signed X.509 Certificate & Key Generator"),
	)
	return header
}

// RunInteractiveForm prompts the user for certificate generation settings via Charm Huh.
func RunInteractiveForm() (*cert.Config, error) {
	fmt.Println(Banner())

	data := FormData{
		Role:         string(cert.RoleLeaf),
		KeyType:      string(cert.KeyTypeECDSAP256),
		CommonName:   "localhost",
		Organization: "Internal / Dev",
		Unit:         "",
		Country:      "US",
		SANDNS:       "localhost, 127.0.0.1",
		SANIP:        "127.0.0.1, ::1",
		ValidityDays: "365",
		OutputDir:    "./",
		NamingScheme: "pem",
		GenPKCS12:    false,
		P12Password:  "",
	}

	theme := huh.ThemeCharm()

	// Step 1: Role & Cryptographic Algorithm
	groupRoleAndKey := huh.NewGroup(
		huh.NewSelect[string]().
			Title("Certificate Role").
			Description("Choose whether this certificate acts as an End-Entity (Leaf) or Certificate Authority (CA)").
			Options(
				huh.NewOption("Server & Client Certificate (Leaf) - Standard TLS endpoint", string(cert.RoleLeaf)),
				huh.NewOption("Root / Intermediate CA - Signs other certificates", string(cert.RoleCA)),
			).
			Value(&data.Role),

		huh.NewSelect[string]().
			Title("Key Algorithm & Size").
			Description("Select cryptographic key type").
			Options(
				huh.NewOption("ECDSA P-256 (Fast, Modern, Recommended)", string(cert.KeyTypeECDSAP256)),
				huh.NewOption("ECDSA P-384 (High Security Elliptic Curve)", string(cert.KeyTypeECDSAP384)),
				huh.NewOption("RSA 2048-bit (Standard Enterprise Compatibility)", string(cert.KeyTypeRSA2048)),
				huh.NewOption("RSA 4096-bit (Maximum RSA Security)", string(cert.KeyTypeRSA4096)),
			).
			Value(&data.KeyType),
	)

	// Step 2: Subject Identity
	groupIdentity := huh.NewGroup(
		huh.NewInput().
			Title("Common Name (CN)").
			Description("Primary domain name or service identifier").
			Placeholder("e.g. localhost, api.internal, or Root CA Name").
			Value(&data.CommonName).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("common Name (CN) is mandatory")
				}
				return nil
			}),

		huh.NewInput().
			Title("Organization (O)").
			Description("Organization or company name").
			Value(&data.Organization),

		huh.NewInput().
			Title("Organizational Unit (OU)").
			Description("Department or team (Optional)").
			Placeholder("e.g. DevOps, Platform Security").
			Value(&data.Unit),

		huh.NewInput().
			Title("Country Code (C)").
			Description("2-Letter ISO 3166-1 country code (e.g. US, IN, DE, GB)").
			Value(&data.Country).
			Validate(func(s string) error {
				trimmed := strings.TrimSpace(s)
				if trimmed != "" && len(trimmed) != 2 {
					return errors.New("country must be exactly 2 letters or left empty")
				}
				return nil
			}),
	)

	// Step 3: Subject Alternative Names (SANs)
	groupSANs := huh.NewGroup(
		huh.NewInput().
			Title("SAN DNS Names").
			Description("Comma-separated list of hostnames / wildcard domains").
			Placeholder("e.g. localhost, *.internal.dev, service.local").
			Value(&data.SANDNS),

		huh.NewInput().
			Title("SAN IP Addresses").
			Description("Comma-separated list of IP addresses").
			Placeholder("e.g. 127.0.0.1, 10.0.0.1, ::1").
			Value(&data.SANIP).
			Validate(func(s string) error {
				trimmed := strings.TrimSpace(s)
				if trimmed == "" {
					return nil
				}
				parts := strings.Split(trimmed, ",")
				for _, p := range parts {
					item := strings.TrimSpace(p)
					if item != "" && net.ParseIP(item) == nil {
						return fmt.Errorf("invalid IP address in SAN list: %q", item)
					}
				}
				return nil
			}),
	)

	// Step 4: Validity & Output Configuration
	groupOutput := huh.NewGroup(
		huh.NewInput().
			Title("Validity Duration (Days)").
			Description("Number of days before certificate expires [Default: 365, Max: 3650]").
			Value(&data.ValidityDays).
			Validate(func(s string) error {
				n, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil || n <= 0 {
					return errors.New("validity duration must be a positive number of days")
				}
				if n > 3650 {
					return errors.New("validity duration cannot exceed 3650 days (10 years)")
				}
				return nil
			}),

		huh.NewInput().
			Title("Output Directory").
			Description("Folder where certificate and key will be written").
			Value(&data.OutputDir),

		huh.NewSelect[string]().
			Title("Output File Naming Scheme").
			Options(
				huh.NewOption("cert.pem & key.pem (Standard PEM format)", "pem"),
				huh.NewOption("cert.crt & key.key (Web Server / Ingress convention)", "crt"),
			).
			Value(&data.NamingScheme),

		huh.NewConfirm().
			Title("Generate PKCS#12 bundle (.p12 / .pfx)?").
			Description("Useful for Windows CertMgr, IIS, or Java truststores").
			Value(&data.GenPKCS12),
	)

	form := huh.NewForm(groupRoleAndKey, groupIdentity, groupSANs, groupOutput).
		WithTheme(theme)

	if err := form.Run(); err != nil {
		return nil, err
	}

	// If PKCS#12 requested, optionally ask for password
	if data.GenPKCS12 {
		p12Form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("PKCS#12 Export Password").
					Description("Leave empty for passwordless bundle, or enter a secret password").
					EchoMode(huh.EchoModePassword).
					Value(&data.P12Password),
			),
		).WithTheme(theme)

		if err := p12Form.Run(); err != nil {
			return nil, err
		}
	}

	// Convert form data to cert.Config
	days, _ := strconv.Atoi(strings.TrimSpace(data.ValidityDays))
	if days <= 0 {
		days = 365
	}

	dnsList, ipList, err := cert.ParseSANLists(data.SANDNS, data.SANIP)
	if err != nil {
		return nil, err
	}

	certFile := "cert.pem"
	keyFile := "key.pem"
	p12File := "cert.p12"
	if data.NamingScheme == "crt" {
		certFile = "cert.crt"
		keyFile = "key.key"
		p12File = "cert.pfx"
	}

	cfg := &cert.Config{
		Role:               cert.CertRole(data.Role),
		KeyType:            cert.KeyType(data.KeyType),
		CommonName:         strings.TrimSpace(data.CommonName),
		Organization:       strings.TrimSpace(data.Organization),
		OrganizationalUnit: strings.TrimSpace(data.Unit),
		Country:            strings.ToUpper(strings.TrimSpace(data.Country)),
		DNSNames:           dnsList,
		IPAddresses:        ipList,
		ValidityDays:       days,
		OutputDir:          strings.TrimSpace(data.OutputDir),
		CertFileName:       certFile,
		KeyFileName:        keyFile,
		GeneratePKCS12:     data.GenPKCS12,
		PKCS12FileName:     p12File,
		PKCS12Password:     data.P12Password,
		KeyFormat:          "pkcs8",
	}

	return cfg, nil
}

// DisplaySuccess prints an enterprise-grade styled summary of the generated assets.
func DisplaySuccess(res *cert.Result) {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#04B575")).
		Padding(1, 2).
		MarginTop(1).
		MarginBottom(1)

	successBadge := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#000000")).
		Background(lipgloss.Color("#04B575")).
		Padding(0, 1)

	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4"))

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA"))

	var content strings.Builder
	content.WriteString(fmt.Sprintf("%s\n\n", successBadge.Render("CERTIFICATE & PRIVATE KEY GENERATED SUCCESSFULLY")))

	content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Common Name:"), valStyle.Render(res.Certificate.Subject.CommonName)))
	if len(res.Certificate.Subject.Organization) > 0 {
		content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Organization:"), valStyle.Render(strings.Join(res.Certificate.Subject.Organization, ", "))))
	}
	roleLabel := "Leaf (Server & Client Auth)"
	if res.Certificate.IsCA {
		roleLabel = "Certificate Authority (CA)"
	}
	content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Role:"), valStyle.Render(roleLabel)))
	content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Serial Number:"), valStyle.Render(res.SerialNumberHex)))
	content.WriteString(fmt.Sprintf("%s %s to %s\n", labelStyle.Render("Validity Period:"),
		valStyle.Render(res.Certificate.NotBefore.Format("2006-01-02 15:04:05 UTC")),
		valStyle.Render(res.Certificate.NotAfter.Format("2006-01-02 15:04:05 UTC")),
	))

	if len(res.Certificate.DNSNames) > 0 {
		content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SAN DNS:"), valStyle.Render(strings.Join(res.Certificate.DNSNames, ", "))))
	}
	if len(res.Certificate.IPAddresses) > 0 {
		var ips []string
		for _, ip := range res.Certificate.IPAddresses {
			ips = append(ips, ip.String())
		}
		content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SAN IP:"), valStyle.Render(strings.Join(ips, ", "))))
	}

	content.WriteString(fmt.Sprintf("%s %s\n\n", labelStyle.Render("SHA-256 Fingerprint:"), valStyle.Render(res.FingerprintSHA256)))

	pathStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7D7")).Bold(true)
	content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Certificate PEM:"), pathStyle.Render(res.CertPath)))
	content.WriteString(fmt.Sprintf("%s %s %s\n", labelStyle.Render("Private Key PEM:"), pathStyle.Render(res.KeyPath), lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("(Strict 0600 mode)")))
	if res.PKCS12Path != "" {
		content.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("PKCS#12 Bundle:"), pathStyle.Render(res.PKCS12Path)))
	}

	fmt.Println(boxStyle.Render(content.String()))
}

// DisplayError prints a nicely formatted error box.
func DisplayError(err error) {
	errStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#FF4444")).
		Padding(1, 2).
		MarginTop(1)

	badge := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(lipgloss.Color("#FF4444")).
		Padding(0, 1).
		Render("ERROR")

	fmt.Fprintln(os.Stderr, errStyle.Render(fmt.Sprintf("%s %v", badge, err)))
}

