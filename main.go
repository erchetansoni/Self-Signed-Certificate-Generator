package main

import (
	"flag"
	"fmt"
	"os"

	"certgen/internal/cert"
	"certgen/internal/trust"
	"certgen/internal/ui"
	"golang.org/x/term"
)

const (
	Version   = "1.2.0"
	AppTitle  = "CertGen - Air-Gapped EDR-Safe PKI & X.509 Certificate Generator"
	BuildDate = "2026"
)

func main() {
	// Define CLI Flags
	flagSet := flag.NewFlagSet("certgen", flag.ContinueOnError)

	role := flagSet.String("role", "", "Certificate mode: 'ca-leaf' (New Root CA + Leaf), 'existing-ca' (Sign with Existing CA), 'ca' (CA only), 'leaf' (self-signed leaf)")
	keyType := flagSet.String("key-type", "ecdsa-p256", "Key algorithm: 'ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096'")
	cn := flagSet.String("cn", "", "Common Name (CN) [e.g. localhost, app.internal]")
	caCN := flagSet.String("ca-cn", "", "Root CA Common Name [e.g. Internal Local Root CA]")
	caYears := flagSet.Int("ca-years", 10, "Root CA validity duration in years [default: 10 years]")
	caDays := flagSet.Int("ca-days", 0, "Root CA validity duration in days (overrides -ca-years if specified)")
	existingCACert := flagSet.String("ca-cert", "", "Path to existing Root CA certificate (e.g. ./rootCA.pem)")
	existingCAKey := flagSet.String("ca-key", "", "Path to existing Root CA private key (e.g. ./rootCA-key.pem)")
	existingCAPass := flagSet.String("ca-pass", "", "Passphrase for existing Root CA private key (if encrypted)")
	org := flagSet.String("o", "Internal / Dev", "Organization (O)")
	ou := flagSet.String("ou", "", "Organizational Unit (OU)")
	country := flagSet.String("c", "US", "Country code (2-letter ISO 3166-1)")
	sanDNS := flagSet.String("san-dns", "", "Comma-separated DNS SANs (e.g. localhost,*.internal.dev)")
	sanIP := flagSet.String("san-ip", "", "Comma-separated IP SANs (e.g. 127.0.0.1,::1)")
	days := flagSet.Int("days", 365, "Validity duration in days for leaf [1 - 3650]")
	outDir := flagSet.String("out-dir", "./", "Output directory")
	certFile := flagSet.String("cert-name", "cert.pem", "Output certificate filename")
	keyFile := flagSet.String("key-name", "key.pem", "Output private key filename")
	caCertFile := flagSet.String("ca-name", "rootCA.pem", "Output Root CA certificate filename")
	caKeyFile := flagSet.String("ca-key-name", "rootCA-key.pem", "Output Root CA private key filename")
	chainFile := flagSet.String("chain-name", "chain.pem", "Output full chain filename")
	genP12 := flagSet.Bool("p12", false, "Generate PKCS#12 (.p12) bundle")
	p12File := flagSet.String("p12-name", "bundle.p12", "PKCS#12 bundle filename")
	p12Pass := flagSet.String("p12-pass", "", "Password for PKCS#12 bundle")
	keyFormat := flagSet.String("key-format", "pkcs8", "Private key format: 'pkcs8' or 'traditional'")
	installOS := flagSet.Bool("install-os", false, "Install Root CA into OS / system trust store")
	installBrowser := flagSet.Bool("install-browser", false, "Install Root CA for Chrome, Edge, and Firefox")
	nonInteractive := flagSet.Bool("non-interactive", false, "Run in non-interactive / headless CLI mode")
	showVersion := flagSet.Bool("version", false, "Print version and build metadata")

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("%s v%s (%s)\n", AppTitle, Version, BuildDate)
		fmt.Println("Design: Zero runtime sockets, zero child processes, offline air-gap safe, full PKI & Existing CA support.")
		return
	}

	var cfg *cert.Config
	var trustOpts *trust.InstallOptions
	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	// Determine whether to launch interactive TUI or headless mode
	shouldUseTUI := isTerminal && !*nonInteractive && *cn == ""

	if shouldUseTUI {
		var err error
		cfg, trustOpts, err = ui.RunInteractiveForm()
		if err != nil {
			if err.Error() == "user aborted" {
				fmt.Println("\nOperation cancelled by user.")
				os.Exit(0)
			}
			ui.DisplayError(fmt.Errorf("interactive form failed: %w", err))
			os.Exit(1)
		}
	} else {
		// Non-interactive / CLI mode
		if *cn == "" {
			ui.DisplayError(fmt.Errorf("common name (-cn) is required in non-interactive mode. Use --help for usage"))
			os.Exit(1)
		}

		selectedRole := *role
		if selectedRole == "" {
			if *existingCACert != "" && *existingCAKey != "" {
				selectedRole = string(cert.RoleExistingCA)
			} else {
				selectedRole = string(cert.RoleCALeaf)
			}
		}

		calculatedCADays := *caDays
		if calculatedCADays <= 0 {
			if *caYears > 0 {
				calculatedCADays = *caYears * 365
			} else {
				calculatedCADays = 3650
			}
		}

		dnsList, ipList, err := cert.ParseSANLists(*sanDNS, *sanIP)
		if err != nil {
			ui.DisplayError(fmt.Errorf("invalid SAN inputs: %w", err))
			os.Exit(1)
		}

		cfg = &cert.Config{
			Role:               cert.CertRole(selectedRole),
			KeyType:            cert.KeyType(*keyType),
			CommonName:         *cn,
			RootCACommonName:   *caCN,
			ExistingCACertPath: *existingCACert,
			ExistingCAKeyPath:  *existingCAKey,
			ExistingCAPassword: *existingCAPass,
			Organization:       *org,
			OrganizationalUnit: *ou,
			Country:            *country,
			DNSNames:           dnsList,
			IPAddresses:        ipList,
			ValidityDays:       *days,
			RootCAValidityDays: calculatedCADays,
			OutputDir:          *outDir,
			CertFileName:       *certFile,
			KeyFileName:        *keyFile,
			RootCAFileName:     *caCertFile,
			RootKeyFileName:    *caKeyFile,
			ChainFileName:      *chainFile,
			GeneratePKCS12:     *genP12,
			PKCS12FileName:     *p12File,
			PKCS12Password:     *p12Pass,
			KeyFormat:          *keyFormat,
		}

		trustOpts = &trust.InstallOptions{
			InstallOS:       *installOS,
			InstallBrowsers: *installBrowser,
		}
	}

	// 1. Generate certificates and private keys
	res, err := cert.Generate(*cfg)
	if err != nil {
		ui.DisplayError(fmt.Errorf("generation failed: %w", err))
		os.Exit(1)
	}

	// 2. Perform OS / Browser Trust Store Installation if applicable
	var report *trust.InstallReport

	if res.IsExistingCA {
		report = &trust.InstallReport{
			OSInstalled:    true,
			OSMessage:      fmt.Sprintf("Using pre-existing Root CA %q (Already trusted by OS / browsers)", res.RootCACertificate.Subject.CommonName),
			ChromeStatus:   "Trusted via pre-existing Root CA",
			EdgeStatus:     "Trusted via pre-existing Root CA",
			FirefoxMessage: "Trusted via pre-existing Root CA",
			ManualCommands: trust.GenerateManualInstructions(res.RootCAPath),
		}
	} else {
		targetCADER := res.RootCADER
		targetCAPEM := res.RootCAPEM
		targetCAPath := res.RootCAPath

		if len(targetCADER) == 0 && cfg.Role == cert.RoleCA {
			targetCADER = res.CertificateDER
			targetCAPEM = res.CertificatePEM
			targetCAPath = res.CertPath
		}

		if len(targetCADER) > 0 {
			report, err = trust.InstallRootCA(targetCADER, targetCAPEM, targetCAPath, *trustOpts)
			if err != nil {
				ui.DisplayError(fmt.Errorf("trust installation warning: %w", err))
			}
		} else {
			report = &trust.InstallReport{
				OSInstalled:    false,
				OSMessage:      "Standalone leaf certificate. Install directly if needed, or use Root CA mode for automatic trust.",
				ManualCommands: trust.GenerateManualInstructions(res.CertPath),
			}
		}
	}

	// 3. Display completion summary
	ui.DisplaySuccess(res, report)
}
