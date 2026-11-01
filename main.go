// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"certgen/internal/cert"
	"certgen/internal/trust"
	"certgen/internal/ui"
	"golang.org/x/term"
)

const (
	AppName   = "Self-Signed Certificate Generator"
	Version   = "1.2.0"
	Author    = "Er. Chetan Soni"
	Website   = "https://ErChetanSoni.github.io/"
	License   = "GNU GPLv3 / Commercial Dual-License"
	BuildDate = "2026"
)

func main() {
	// Define CLI Flags
	flagSet := flag.NewFlagSet("certgen", flag.ContinueOnError)

	var (
		role           string
		keyType        string
		cn             string
		caCN           string
		caYears        int
		caDays         int
		existingCACert string
		existingCAKey  string
		existingCAPass string
		org            string
		ou             string
		country        string
		sanDNS         string
		sanIP          string
		days           int
		outDir         string
		certFile       string
		keyFile        string
		caCertFile     string
		caKeyFile      string
		chainFile      string
		genP12         bool
		p12File        string
		p12Pass        string
		keyFormat      string
		installOS      bool
		installBrowser bool
		nonInteractive bool
		showVersion    bool
	)

	// Certificate Role / Hierarchy Mode (-r, --role)
	flagSet.StringVar(&role, "role", "", "Certificate mode: 'ca-leaf', 'existing-ca', 'ca', 'leaf'")
	flagSet.StringVar(&role, "r", "", "Alias for --role")

	// Key Algorithm (-k, --key-type)
	flagSet.StringVar(&keyType, "key-type", "ecdsa-p256", "Key algorithm: 'ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096'")
	flagSet.StringVar(&keyType, "k", "ecdsa-p256", "Alias for --key-type")

	// Common Name (--cn, --common-name)
	flagSet.StringVar(&cn, "cn", "", "Common Name (CN) [e.g. localhost, app.internal]")
	flagSet.StringVar(&cn, "common-name", "", "Alias for --cn")

	// Root CA options (-y, --ca-years)
	flagSet.StringVar(&caCN, "ca-cn", "", "Root CA Common Name [e.g. Internal Local Root CA]")
	flagSet.IntVar(&caYears, "ca-years", 10, "Root CA validity duration in years [default: 10 years]")
	flagSet.IntVar(&caYears, "y", 10, "Alias for --ca-years")
	flagSet.IntVar(&caYears, "years", 10, "Alias for --ca-years")
	flagSet.IntVar(&caDays, "ca-days", 0, "Root CA validity duration in days (overrides --ca-years if specified)")
	flagSet.StringVar(&existingCACert, "ca-cert", "", "Path to existing Root CA certificate (e.g. ./rootCA.pem)")
	flagSet.StringVar(&existingCAKey, "ca-key", "", "Path to existing Root CA private key (e.g. ./rootCA-key.pem)")
	flagSet.StringVar(&existingCAPass, "ca-pass", "", "Passphrase for existing Root CA private key (if encrypted)")

	// Subject Identity (-o, --org, -c, --country, --ou)
	flagSet.StringVar(&org, "org", "Internal / Dev", "Organization (O)")
	flagSet.StringVar(&org, "o", "Internal / Dev", "Alias for --org")
	flagSet.StringVar(&org, "organization", "Internal / Dev", "Alias for --org")

	flagSet.StringVar(&ou, "ou", "", "Organizational Unit (OU)")

	flagSet.StringVar(&country, "country", "US", "Country code (2-letter ISO 3166-1)")
	flagSet.StringVar(&country, "c", "US", "Alias for --country")

	// Subject Alternative Names (--dns, --san-dns, --ip, --san-ip)
	flagSet.StringVar(&sanDNS, "san-dns", "", "Comma-separated DNS SANs (e.g. localhost,*.internal.dev)")
	flagSet.StringVar(&sanDNS, "dns", "", "Alias for --san-dns")

	flagSet.StringVar(&sanIP, "san-ip", "", "Comma-separated IP SANs (e.g. 127.0.0.1,::1)")
	flagSet.StringVar(&sanIP, "ip", "", "Alias for --san-ip")

	// Leaf Validity (-d, --days)
	flagSet.IntVar(&days, "days", 365, "Validity duration in days for leaf [1 - 3650]")
	flagSet.IntVar(&days, "d", 365, "Alias for --days")

	// Output Directory (--out-dir, --output, --out)
	flagSet.StringVar(&outDir, "out-dir", "./", "Output directory")
	flagSet.StringVar(&outDir, "output", "./", "Alias for --out-dir")
	flagSet.StringVar(&outDir, "out", "./", "Alias for --out-dir")

	// Filenames
	flagSet.StringVar(&certFile, "cert-name", "cert.pem", "Output certificate filename")
	flagSet.StringVar(&keyFile, "key-name", "key.pem", "Output private key filename")
	flagSet.StringVar(&caCertFile, "ca-name", "rootCA.pem", "Output Root CA certificate filename")
	flagSet.StringVar(&caKeyFile, "ca-key-name", "rootCA-key.pem", "Output Root CA private key filename")
	flagSet.StringVar(&chainFile, "chain-name", "chain.pem", "Output full chain filename")

	// PKCS#12 bundle (--p12, --pfx)
	flagSet.BoolVar(&genP12, "p12", false, "Generate PKCS#12 (.p12) bundle")
	flagSet.BoolVar(&genP12, "pfx", false, "Alias for --p12")
	flagSet.StringVar(&p12File, "p12-name", "bundle.p12", "PKCS#12 bundle filename")
	flagSet.StringVar(&p12Pass, "p12-pass", "", "Password for PKCS#12 bundle")

	// Advanced & trust flags
	flagSet.StringVar(&keyFormat, "key-format", "pkcs8", "Private key format: 'pkcs8' or 'traditional'")
	flagSet.BoolVar(&installOS, "install-os", false, "Install Root CA into OS / system trust store")
	flagSet.BoolVar(&installBrowser, "install-browser", false, "Install Root CA for Chrome, Edge, and Firefox")

	// Execution & Info (-b, --batch, --non-interactive, -v, --version)
	flagSet.BoolVar(&nonInteractive, "non-interactive", false, "Run in non-interactive / headless CLI mode")
	flagSet.BoolVar(&nonInteractive, "batch", false, "Alias for --non-interactive")
	flagSet.BoolVar(&nonInteractive, "b", false, "Alias for --non-interactive")

	flagSet.BoolVar(&showVersion, "version", false, "Print version, author, and licensing metadata")
	flagSet.BoolVar(&showVersion, "v", false, "Alias for --version")

	// Custom formatted usage for --help / -h
	flagSet.Usage = func() {
		fmt.Printf("%s v%s (%s)\n", AppName, Version, BuildDate)
		fmt.Printf("Author:  %s (%s)\n", Author, Website)
		fmt.Printf("License: %s\n\n", License)
		fmt.Println("A modern, air-gapped, EDR-safe PKI and self-signed certificate generator.")
		fmt.Println()
		fmt.Println("USAGE:")
		fmt.Println("  certgen [flags]")
		fmt.Println()
		fmt.Println("EXAMPLES:")
		fmt.Println("  # Launch interactive TUI form (default):")
		fmt.Println("  certgen")
		fmt.Println()
		fmt.Println("  # Generate Root CA + signed Leaf cert using full options (long flags):")
		fmt.Println("  certgen --role ca-leaf --cn app.internal --days 365 --ca-years 10 --out-dir ./certs")
		fmt.Println()
		fmt.Println("  # Quick command using single-letter shortcuts:")
		fmt.Println("  certgen -r ca-leaf --cn app.internal -d 365 -y 10 -b --out-dir ./certs")
		fmt.Println()
		fmt.Println("  # Sign a new leaf cert with an existing Root CA:")
		fmt.Println("  certgen -r existing-ca --cn api.internal --ca-cert ./rootCA.pem --ca-key ./rootCA-key.pem")
		fmt.Println()
		fmt.Println("FLAGS:")
		fmt.Println("  Certificate & PKI Options:")
		fmt.Println("    -r, --role <mode>            Certificate mode: 'ca-leaf' (default), 'existing-ca', 'ca', 'leaf'")
		fmt.Println("        --cn, --common-name <CN> Common Name (e.g. localhost, app.internal)")
		fmt.Println("    -d, --days <count>           Leaf certificate validity in days (default: 365)")
		fmt.Println("    -k, --key-type <type>        Key algorithm: 'ecdsa-p256' (default), 'ecdsa-p384', 'rsa-2048', 'rsa-4096'")
		fmt.Println("        --dns, --san-dns <list>  Comma-separated DNS SANs (e.g. localhost,*.app.internal)")
		fmt.Println("        --ip, --san-ip <list>    Comma-separated IP SANs (e.g. 127.0.0.1,10.0.0.1)")
		fmt.Println()
		fmt.Println("  Root CA Configuration:")
		fmt.Println("        --ca-cn <name>           Root CA Common Name (default: '<CN> Root CA')")
		fmt.Println("    -y, --ca-years <years>       Root CA validity duration in years (default: 10)")
		fmt.Println("        --ca-days <days>         Root CA validity in days (overrides --ca-years if set)")
		fmt.Println("        --ca-cert <path>         Path to existing Root CA certificate (e.g. ./rootCA.pem)")
		fmt.Println("        --ca-key <path>          Path to existing Root CA private key (e.g. ./rootCA-key.pem)")
		fmt.Println("        --ca-pass <pass>         Passphrase for existing Root CA private key")
		fmt.Println()
		fmt.Println("  Subject Identity (X.509):")
		fmt.Println("    -o, --org <name>             Organization (O) (default: 'Internal / Dev')")
		fmt.Println("        --ou <unit>              Organizational Unit (OU)")
		fmt.Println("    -c, --country <code>         Country code (2-letter ISO 3166-1) (default: 'US')")
		fmt.Println()
		fmt.Println("  Output & Bundle Options:")
		fmt.Println("        --out-dir, --output <dir> Output directory (default: './')")
		fmt.Println("        --cert-name <file>       Leaf certificate filename (default: 'cert.pem')")
		fmt.Println("        --key-name <file>        Leaf private key filename (default: 'key.pem')")
		fmt.Println("        --ca-name <file>         Root CA certificate filename (default: 'rootCA.pem')")
		fmt.Println("        --ca-key-name <file>     Root CA private key filename (default: 'rootCA-key.pem')")
		fmt.Println("        --chain-name <file>      Full chain filename (default: 'chain.pem')")
		fmt.Println("        --key-format <format>    Private key format: 'pkcs8' (default) or 'traditional'")
		fmt.Println("        --p12, --pfx             Generate PKCS#12 (.p12 / .pfx) bundle")
		fmt.Println("        --p12-name <file>        PKCS#12 bundle filename (default: 'bundle.p12')")
		fmt.Println("        --p12-pass <pass>        Password for PKCS#12 bundle")
		fmt.Println()
		fmt.Println("  Trust Store Installation:")
		fmt.Println("        --install-os             Install Root CA into OS / system trust store")
		fmt.Println("        --install-browser        Install Root CA for Chrome, Edge, and Firefox")
		fmt.Println()
		fmt.Println("  General Flags:")
		fmt.Println("    -b, --batch,")
		fmt.Println("    --non-interactive            Run in non-interactive / headless CLI mode")
		fmt.Println("    -v, --version                Print version, author, and licensing metadata")
		fmt.Println("    -h, --help                   Show this help message")
	}

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf("%s v%s (%s)\n", AppName, Version, BuildDate)
		fmt.Printf("Author:  %s (%s)\n", Author, Website)
		fmt.Printf("License: %s\n", License)
		fmt.Println("Design:  Zero runtime sockets, zero child processes, offline air-gap safe, full PKI & Existing CA support.")
		return
	}

	var cfg *cert.Config
	var trustOpts *trust.InstallOptions
	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	// Determine whether to launch interactive TUI or headless mode
	shouldUseTUI := isTerminal && !nonInteractive && cn == ""

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
		if cn == "" {
			ui.DisplayError(fmt.Errorf("common name (--cn) is required in non-interactive mode. Use --help for usage"))
			os.Exit(1)
		}

		selectedRole := role
		if selectedRole == "" {
			if existingCACert != "" && existingCAKey != "" {
				selectedRole = string(cert.RoleExistingCA)
			} else {
				selectedRole = string(cert.RoleCALeaf)
			}
		}

		calculatedCADays := caDays
		if calculatedCADays <= 0 {
			if caYears > 0 {
				calculatedCADays = caYears * 365
			} else {
				calculatedCADays = 3650
			}
		}

		dnsList, ipList, err := cert.ParseSANLists(sanDNS, sanIP)
		if err != nil {
			ui.DisplayError(fmt.Errorf("invalid SAN inputs: %w", err))
			os.Exit(1)
		}

		cfg = &cert.Config{
			Role:               cert.CertRole(selectedRole),
			KeyType:            cert.KeyType(keyType),
			CommonName:         cn,
			RootCACommonName:   caCN,
			ExistingCACertPath: existingCACert,
			ExistingCAKeyPath:  existingCAKey,
			ExistingCAPassword: existingCAPass,
			Organization:       org,
			OrganizationalUnit: ou,
			Country:            country,
			DNSNames:           dnsList,
			IPAddresses:        ipList,
			ValidityDays:       days,
			RootCAValidityDays: calculatedCADays,
			OutputDir:          outDir,
			CertFileName:       certFile,
			KeyFileName:        keyFile,
			RootCAFileName:     caCertFile,
			RootKeyFileName:    caKeyFile,
			ChainFileName:      chainFile,
			GeneratePKCS12:     genP12,
			PKCS12FileName:     p12File,
			PKCS12Password:     p12Pass,
			KeyFormat:          keyFormat,
		}

		trustOpts = &trust.InstallOptions{
			InstallOS:       installOS,
			InstallBrowsers: installBrowser,
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
