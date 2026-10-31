package ui

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"certgen/internal/cert"
	"certgen/internal/trust"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// FormData holds interactive user choices from the TUI form.
type FormData struct {
	Role                string
	KeyType             string
	CommonName          string
	RootCAName          string
	RootCAValidityYears string
	ExistingCACert      string
	ExistingCAKey       string
	ExistingCAPass      string
	Organization        string
	Unit                string
	Country             string
	SANDNS              string
	SANIP               string
	ValidityDays        string
	OutputDir           string
	NamingScheme        string
	GenPKCS12           bool
	P12Password         string
	InstallOS           bool
	InstallBrowsers     bool
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
		SetString("[EDR-Safe / Air-Gapped / Zero-Network / Full PKI]")

	header := fmt.Sprintf("%s  %s\n%s\n",
		titleStyle.Render("CERTGEN"),
		secBadge.Render(),
		subTitleStyle.Render("Production-Grade Self-Signed X.509 PKI & Certificate Authority Generator"),
	)
	return header
}

// RunInteractiveForm prompts the user for certificate generation settings via Charm Huh.
func RunInteractiveForm() (*cert.Config, *trust.InstallOptions, error) {
	fmt.Println(Banner())

	// Auto-detect if an existing Root CA is present in current folder or parent
	detectedCA := cert.DetectExistingCA()

	defaultRole := string(cert.RoleCALeaf)
	defaultCACert := "./rootCA.pem"
	defaultCAKey := "./rootCA-key.pem"

	if detectedCA != nil {
		defaultRole = string(cert.RoleExistingCA)
		defaultCACert = detectedCA.CertPath
		defaultCAKey = detectedCA.KeyPath

		noticeStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#00D7D7")).
			Padding(0, 1).
			MarginBottom(1)

		badge := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D7D7")).Render("✔ EXISTING ROOT CA DETECTED:")
		details := fmt.Sprintf("%s %q found in %s (Valid until %s)",
			badge,
			detectedCA.CommonName,
			detectedCA.CertPath,
			detectedCA.ExpiresAt.Format("2006-01-02"),
		)
		fmt.Println(noticeStyle.Render(details))
	}

	data := FormData{
		Role:                defaultRole,
		KeyType:             string(cert.KeyTypeECDSAP256),
		CommonName:          "localhost",
		RootCAName:          "Internal Development Root CA",
		RootCAValidityYears: "10",
		ExistingCACert:      defaultCACert,
		ExistingCAKey:       defaultCAKey,
		Organization:        "Internal / Dev",
		Unit:                "",
		Country:             "US",
		SANDNS:              "localhost, 127.0.0.1",
		SANIP:               "127.0.0.1, ::1",
		ValidityDays:        "365",
		OutputDir:           "./",
		NamingScheme:        "pem",
		GenPKCS12:           false,
		P12Password:         "",
		InstallOS:           detectedCA == nil,
		InstallBrowsers:     detectedCA == nil,
	}

	theme := huh.ThemeCharm()

	// Build Role options
	var roleOptions []huh.Option[string]
	if detectedCA != nil {
		roleOptions = append(roleOptions,
			huh.NewOption(fmt.Sprintf("Sign with Detected Root CA (%s) [Recommended]", detectedCA.CommonName), string(cert.RoleExistingCA)),
			huh.NewOption("Generate NEW Root CA + Signed Leaf Certificate", string(cert.RoleCALeaf)),
			huh.NewOption("Sign with another Existing Root CA (Specify custom paths)", "custom-existing-ca"),
			huh.NewOption("Root / Intermediate CA Only - For signing other certificates", string(cert.RoleCA)),
			huh.NewOption("Standalone Self-Signed Leaf Only - Direct self-signed without CA", string(cert.RoleLeaf)),
		)
	} else {
		roleOptions = append(roleOptions,
			huh.NewOption("Generate NEW Root CA + Signed Leaf Certificate (Recommended)", string(cert.RoleCALeaf)),
			huh.NewOption("Sign with an Existing Root CA (Specify path to rootCA.pem & rootCA-key.pem)", string(cert.RoleExistingCA)),
			huh.NewOption("Root / Intermediate CA Only - For signing other certificates", string(cert.RoleCA)),
			huh.NewOption("Standalone Self-Signed Leaf Only - Direct self-signed without CA", string(cert.RoleLeaf)),
		)
	}

	// Step 1: Role & Key Algorithm
	groupRoleAndKey := huh.NewGroup(
		huh.NewSelect[string]().
			Title("Certificate Hierarchy / Role").
			Description("Choose generation mode").
			Options(roleOptions...).
			Value(&data.Role),

		huh.NewSelect[string]().
			Title("Key Algorithm & Size").
			Description("Select cryptographic key type for the certificate").
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
			Placeholder("e.g. localhost, api.internal, or service name").
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
			Title("Leaf Certificate Validity Duration (Days)").
			Description("Number of days before leaf certificate expires [Default: 365 (1 year), Max: 3650]").
			Value(&data.ValidityDays).
			Validate(func(s string) error {
				n, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil || n <= 0 {
					return errors.New("leaf validity duration must be a positive number of days")
				}
				if n > 3650 {
					return errors.New("leaf validity duration cannot exceed 3650 days (10 years)")
				}
				return nil
			}),

		huh.NewInput().
			Title("Output Directory").
			Description("Folder where certificates and keys will be written").
			Value(&data.OutputDir),

		huh.NewSelect[string]().
			Title("Output File Naming Scheme").
			Options(
				huh.NewOption("cert.pem, rootCA.pem & key.pem (Standard PEM format)", "pem"),
				huh.NewOption("cert.crt, rootCA.crt & key.key (Web Server / Ingress convention)", "crt"),
			).
			Value(&data.NamingScheme),

		huh.NewConfirm().
			Title("Generate PKCS#12 bundle (.p12 / .pfx)?").
			Description("Contains leaf certificate, private key, and Root CA chain").
			Value(&data.GenPKCS12),
	)

	form := huh.NewForm(groupRoleAndKey, groupIdentity, groupSANs, groupOutput).
		WithTheme(theme)

	if err := form.Run(); err != nil {
		return nil, nil, err
	}

	// Normalize custom-existing-ca selection
	if data.Role == "custom-existing-ca" {
		data.Role = string(cert.RoleExistingCA)
	}

	// Case 1: Using an existing Root CA
	if data.Role == string(cert.RoleExistingCA) {
		existingCAForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Existing Root CA Certificate Path").
					Description("Path to your existing rootCA.pem or rootCA.crt").
					Value(&data.ExistingCACert).
					Validate(func(s string) error {
						if strings.TrimSpace(s) == "" {
							return errors.New("path to Root CA certificate is required")
						}
						if _, err := os.Stat(strings.TrimSpace(s)); err != nil {
							return fmt.Errorf("file not found: %s", s)
						}
						return nil
					}),

				huh.NewInput().
					Title("Existing Root CA Private Key Path").
					Description("Path to your existing rootCA-key.pem or rootCA.key").
					Value(&data.ExistingCAKey).
					Validate(func(s string) error {
						if strings.TrimSpace(s) == "" {
							return errors.New("path to Root CA private key is required")
						}
						if _, err := os.Stat(strings.TrimSpace(s)); err != nil {
							return fmt.Errorf("file not found: %s", s)
						}
						return nil
					}),

				huh.NewInput().
					Title("Root CA Key Passphrase (Optional)").
					Description("Leave empty if your Root CA private key is unencrypted").
					EchoMode(huh.EchoModePassword).
					Value(&data.ExistingCAPass),
			),
		).WithTheme(theme)

		if err := existingCAForm.Run(); err != nil {
			return nil, nil, err
		}
	} else if data.Role == string(cert.RoleCALeaf) || data.Role == string(cert.RoleCA) {
		// Case 2: Generating a NEW Root CA -> Ask for Root CA Name, Validity in YEARS, and Trust install
		newCAForm := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Root CA Common Name").
					Description("Name of the new Root Certification Authority").
					Value(&data.RootCAName),

				huh.NewInput().
					Title("Root CA Validity Duration (Years)").
					Description("How many YEARS should the Root CA remain valid? [Default: 10 years, e.g. 5, 10, 20, 30]").
					Value(&data.RootCAValidityYears).
					Validate(func(s string) error {
						n, err := strconv.Atoi(strings.TrimSpace(s))
						if err != nil || n <= 0 {
							return errors.New("Root CA validity must be a positive number of years (e.g. 5, 10, 20)")
						}
						if n > 50 {
							return errors.New("Root CA validity duration cannot exceed 50 years")
						}
						return nil
					}),

				huh.NewConfirm().
					Title("Install new Root CA into OS Trust Store?").
					Description("Enables automatic trust in Windows (10/11/Server), Linux (Ubuntu/Debian/RHEL)").
					Value(&data.InstallOS),

				huh.NewConfirm().
					Title("Install new Root CA for Browsers?").
					Description("Enables automatic trust in Google Chrome, Microsoft Edge, and Mozilla Firefox").
					Value(&data.InstallBrowsers),
			),
		).WithTheme(theme)

		if err := newCAForm.Run(); err != nil {
			return nil, nil, err
		}
	}

	// If PKCS#12 requested, prompt for password
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
			return nil, nil, err
		}
	}

	leafDays, _ := strconv.Atoi(strings.TrimSpace(data.ValidityDays))
	if leafDays <= 0 {
		leafDays = 365
	}

	caYears, _ := strconv.Atoi(strings.TrimSpace(data.RootCAValidityYears))
	if caYears <= 0 {
		caYears = 10
	}
	caDays := caYears * 365

	dnsList, ipList, err := cert.ParseSANLists(data.SANDNS, data.SANIP)
	if err != nil {
		return nil, nil, err
	}

	certFile := "cert.pem"
	keyFile := "key.pem"
	rootCertFile := "rootCA.pem"
	rootKeyFile := "rootCA-key.pem"
	chainFile := "chain.pem"
	p12File := "bundle.p12"

	if data.NamingScheme == "crt" {
		certFile = "cert.crt"
		keyFile = "key.key"
		rootCertFile = "rootCA.crt"
		rootKeyFile = "rootCA.key"
		chainFile = "chain.crt"
		p12File = "bundle.pfx"
	}

	cfg := &cert.Config{
		Role:               cert.CertRole(data.Role),
		KeyType:            cert.KeyType(data.KeyType),
		CommonName:         strings.TrimSpace(data.CommonName),
		RootCACommonName:   strings.TrimSpace(data.RootCAName),
		ExistingCACertPath: strings.TrimSpace(data.ExistingCACert),
		ExistingCAKeyPath:  strings.TrimSpace(data.ExistingCAKey),
		ExistingCAPassword: data.ExistingCAPass,
		Organization:       strings.TrimSpace(data.Organization),
		OrganizationalUnit: strings.TrimSpace(data.Unit),
		Country:            strings.ToUpper(strings.TrimSpace(data.Country)),
		DNSNames:           dnsList,
		IPAddresses:        ipList,
		ValidityDays:       leafDays,
		RootCAValidityDays: caDays,
		OutputDir:          strings.TrimSpace(data.OutputDir),
		CertFileName:       certFile,
		KeyFileName:        keyFile,
		RootCAFileName:     rootCertFile,
		RootKeyFileName:    rootKeyFile,
		ChainFileName:      chainFile,
		GeneratePKCS12:     data.GenPKCS12,
		PKCS12FileName:     p12File,
		PKCS12Password:     data.P12Password,
		KeyFormat:          "pkcs8",
	}

	opts := &trust.InstallOptions{
		InstallOS:       data.InstallOS,
		InstallBrowsers: data.InstallBrowsers,
	}

	return cfg, opts, nil
}

// DisplaySuccess prints an enterprise-grade styled summary of generated certificates and trust status.
func DisplaySuccess(res *cert.Result, report *trust.InstallReport) {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#04B575")).
		Padding(1, 2).
		MarginTop(1).
		MarginBottom(1)

	headerBadge := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#000000")).
		Background(lipgloss.Color("#04B575")).
		Padding(0, 1)

	sectionStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FFD700")).
		MarginTop(1)

	labelStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4"))

	valStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FAFAFA"))

	pathStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00D7D7")).
		Bold(true)

	statusGood := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#04B575")).
		Bold(true)

	var sb strings.Builder

	title := "CERTIFICATES & KEYS GENERATED SUCCESSFULLY"
	if res.IsExistingCA {
		title = "LEAF CERTIFICATE SIGNED BY EXISTING ROOT CA"
	} else if res.IsPKI {
		title = "NEW ROOT CA & SIGNED LEAF CERTIFICATE GENERATED"
	}
	sb.WriteString(fmt.Sprintf("%s\n\n", headerBadge.Render(title)))

	// Section 1: Root CA Details
	if res.IsPKI {
		headerLabel := "── ROOT CERTIFICATE AUTHORITY (ROOT CA) ──"
		if res.IsExistingCA {
			headerLabel = "── SIGNED USING EXISTING ROOT CA ──"
		}
		sb.WriteString(fmt.Sprintf("%s\n", sectionStyle.Render(headerLabel)))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Name:"), valStyle.Render(res.RootCACertificate.Subject.CommonName)))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Serial:"), valStyle.Render(res.RootCASerialHex)))
		sb.WriteString(fmt.Sprintf("%s %s to %s\n", labelStyle.Render("Root CA Validity:"),
			valStyle.Render(res.RootCACertificate.NotBefore.Format("2006-01-02 15:04:05 UTC")),
			valStyle.Render(res.RootCACertificate.NotAfter.Format("2006-01-02 15:04:05 UTC")),
		))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Fingerprint:"), valStyle.Render(res.RootCAFingerprint)))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Certificate:"), pathStyle.Render(res.RootCAPath)))
		if !res.IsExistingCA {
			sb.WriteString(fmt.Sprintf("%s %s %s\n", labelStyle.Render("Root CA Private Key:"), pathStyle.Render(res.RootCAKeyPath), lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("(Strict 0600)")))
		} else {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Status:"), statusGood.Render("Reused existing CA (Already trusted by OS/browsers)")))
		}
		sb.WriteString("\n")
	}

	// Section 2: Leaf Certificate Details
	if res.Certificate != nil && res.CertPath != "" {
		sb.WriteString(fmt.Sprintf("%s\n", sectionStyle.Render("── LEAF CERTIFICATE (SERVER & CLIENT) ──")))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Common Name (CN):"), valStyle.Render(res.Certificate.Subject.CommonName)))
		if len(res.Certificate.Subject.Organization) > 0 {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Organization (O):"), valStyle.Render(strings.Join(res.Certificate.Subject.Organization, ", "))))
		}
		if res.IsPKI {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Issuer / Signed By:"), statusGood.Render(res.RootCACertificate.Subject.CommonName)))
		}
		sb.WriteString(fmt.Sprintf("%s %s to %s\n", labelStyle.Render("Validity Period:"),
			valStyle.Render(res.Certificate.NotBefore.Format("2006-01-02 15:04:05 UTC")),
			valStyle.Render(res.Certificate.NotAfter.Format("2006-01-02 15:04:05 UTC")),
		))
		if len(res.Certificate.DNSNames) > 0 {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SAN DNS:"), valStyle.Render(strings.Join(res.Certificate.DNSNames, ", "))))
		}
		if len(res.Certificate.IPAddresses) > 0 {
			var ips []string
			for _, ip := range res.Certificate.IPAddresses {
				ips = append(ips, ip.String())
			}
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SAN IP:"), valStyle.Render(strings.Join(ips, ", "))))
		}
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("SHA-256 Fingerprint:"), valStyle.Render(res.FingerprintSHA256)))
		sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Certificate PEM:"), pathStyle.Render(res.CertPath)))
		sb.WriteString(fmt.Sprintf("%s %s %s\n", labelStyle.Render("Private Key PEM:"), pathStyle.Render(res.KeyPath), lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("(Strict 0600)")))
		if res.ChainPath != "" {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Full Chain PEM:"), pathStyle.Render(res.ChainPath)))
		}
		if res.PKCS12Path != "" {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("PKCS#12 Bundle:"), pathStyle.Render(res.PKCS12Path)))
		}
		sb.WriteString("\n")
	}

	// Section 3: OS & Browser Trust Status
	if report != nil {
		sb.WriteString(fmt.Sprintf("%s\n", sectionStyle.Render("── OS & BROWSER TRUST STATUS ──")))

		if res.IsExistingCA {
			sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Root CA Trust:"), statusGood.Render("Signed by existing trusted Root CA. All browsers already trust this certificate.")))
		} else {
			osIcon := "✔"
			if !report.OSInstalled {
				osIcon = "⚠"
			}
			sb.WriteString(fmt.Sprintf("%s %s %s\n", labelStyle.Render("System / OS Store:"), osIcon, valStyle.Render(report.OSMessage)))

			if report.ChromeStatus != "" {
				sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Google Chrome:"), statusGood.Render(report.ChromeStatus)))
			}
			if report.EdgeStatus != "" {
				sb.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Microsoft Edge:"), statusGood.Render(report.EdgeStatus)))
			}
			if report.FirefoxMessage != "" {
				ffIcon := "✔"
				if !report.FirefoxInstalled {
					ffIcon = "ℹ"
				}
				sb.WriteString(fmt.Sprintf("%s %s %s\n", labelStyle.Render("Mozilla Firefox:"), ffIcon, valStyle.Render(report.FirefoxMessage)))
			}
		}

		if len(report.ManualCommands) > 0 {
			sb.WriteString(fmt.Sprintf("\n%s\n", sectionStyle.Render("── MANUAL / CROSS-PLATFORM INSTALL COMMANDS ──")))
			for _, cmd := range report.ManualCommands {
				sb.WriteString(fmt.Sprintf("  %s:\n    %s\n",
					lipgloss.NewStyle().Foreground(lipgloss.Color("#5A56E0")).Bold(true).Render(cmd.Platform),
					lipgloss.NewStyle().Foreground(lipgloss.Color("#A0A0A0")).Render(cmd.Command),
				))
			}
		}
	}

	fmt.Println(boxStyle.Render(sb.String()))
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
