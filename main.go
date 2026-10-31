package main

import (
	"flag"
	"fmt"
	"os"

	"certgen/internal/cert"
	"certgen/internal/ui"
	"golang.org/x/term"
)

const (
	Version   = "1.0.0.0"
	AppTitle  = "CertGen - Air-Gapped EDR-Safe X.509 Certificate Generator"
	BuildDate = "2026"
)

func main() {
	// Define CLI Flags
	flagSet := flag.NewFlagSet("certgen", flag.ContinueOnError)

	role := flagSet.String("role", "leaf", "Certificate role: 'leaf' (Server/Client) or 'ca' (Root/Intermediate CA)")
	keyType := flagSet.String("key-type", "ecdsa-p256", "Key algorithm: 'ecdsa-p256', 'ecdsa-p384', 'rsa-2048', 'rsa-4096'")
	cn := flagSet.String("cn", "", "Common Name (CN) [e.g. localhost, app.internal]")
	org := flagSet.String("o", "Internal / Dev", "Organization (O)")
	ou := flagSet.String("ou", "", "Organizational Unit (OU)")
	country := flagSet.String("c", "US", "Country code (2-letter ISO 3166-1)")
	sanDNS := flagSet.String("san-dns", "", "Comma-separated DNS SANs (e.g. localhost,*.internal.dev)")
	sanIP := flagSet.String("san-ip", "", "Comma-separated IP SANs (e.g. 127.0.0.1,::1)")
	days := flagSet.Int("days", 365, "Validity duration in days [1 - 3650]")
	outDir := flagSet.String("out-dir", "./", "Output directory")
	certFile := flagSet.String("cert-name", "cert.pem", "Output certificate filename")
	keyFile := flagSet.String("key-name", "key.pem", "Output private key filename")
	genP12 := flagSet.Bool("p12", false, "Generate PKCS#12 (.p12) bundle")
	p12File := flagSet.String("p12-name", "cert.p12", "PKCS#12 bundle filename")
	p12Pass := flagSet.String("p12-pass", "", "Password for PKCS#12 bundle")
	keyFormat := flagSet.String("key-format", "pkcs8", "Private key format: 'pkcs8' or 'traditional'")
	nonInteractive := flagSet.Bool("non-interactive", false, "Run in non-interactive / headless CLI mode")
	showVersion := flagSet.Bool("version", false, "Print version and build metadata")

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	if *showVersion {
		fmt.Printf("%s v%s (%s)\n", AppTitle, Version, BuildDate)
		fmt.Println("Design: Zero runtime sockets, zero child processes, offline air-gap safe.")
		return
	}

	var cfg *cert.Config
	isTerminal := term.IsTerminal(int(os.Stdin.Fd()))

	// Determine whether to launch interactive TUI or headless mode
	shouldUseTUI := isTerminal && !*nonInteractive && *cn == ""

	if shouldUseTUI {
		var err error
		cfg, err = ui.RunInteractiveForm()
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

		dnsList, ipList, err := cert.ParseSANLists(*sanDNS, *sanIP)
		if err != nil {
			ui.DisplayError(fmt.Errorf("invalid SAN inputs: %w", err))
			os.Exit(1)
		}

		cfg = &cert.Config{
			Role:               cert.CertRole(*role),
			KeyType:            cert.KeyType(*keyType),
			CommonName:         *cn,
			Organization:       *org,
			OrganizationalUnit: *ou,
			Country:            *country,
			DNSNames:           dnsList,
			IPAddresses:        ipList,
			ValidityDays:       *days,
			OutputDir:          *outDir,
			CertFileName:       *certFile,
			KeyFileName:        *keyFile,
			GeneratePKCS12:     *genP12,
			PKCS12FileName:     *p12File,
			PKCS12Password:     *p12Pass,
			KeyFormat:          *keyFormat,
		}
	}

	// Generate certificate and private key
	res, err := cert.Generate(*cfg)
	if err != nil {
		ui.DisplayError(fmt.Errorf("generation failed: %w", err))
		os.Exit(1)
	}

	// Display completion summary
	ui.DisplaySuccess(res)
}

