// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package trust

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// InstallOptions specifies which trust stores should be updated.
type InstallOptions struct {
	InstallOS       bool
	InstallBrowsers bool
}

// InstallReport summarizes the outcome of the trust installation across platforms.
type InstallReport struct {
	OSInstalled      bool
	OSMessage        string
	ChromeStatus     string
	EdgeStatus       string
	FirefoxInstalled bool
	FirefoxMessage   string
	ManualCommands   []ManualInstruction
}

// ManualInstruction provides copy-paste commands for various OSes and environments.
type ManualInstruction struct {
	Platform string
	Command  string
}

// FirefoxPolicy represents the enterprise policy structure for Firefox.
type FirefoxPolicy struct {
	Policies struct {
		ImportEnterpriseRoots bool `json:"ImportEnterpriseRoots,omitempty"`
		Certificates          *struct {
			Install []string `json:"Install,omitempty"`
		} `json:"Certificates,omitempty"`
	} `json:"policies"`
}

// GenerateManualInstructions builds copy-paste instructions for every major OS and browser.
func GenerateManualInstructions(certPath string) []ManualInstruction {
	absPath, err := filepath.Abs(certPath)
	if err != nil {
		absPath = certPath
	}

	return []ManualInstruction{
		{
			Platform: "Windows (CMD / PowerShell as Admin)",
			Command:  fmt.Sprintf(`certutil -addstore -f "ROOT" "%s"`, absPath),
		},
		{
			Platform: "Windows PowerShell (Current User - No Admin Needed)",
			Command:  fmt.Sprintf(`Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\CurrentUser\Root`, absPath),
		},
		{
			Platform: "Linux (Debian / Ubuntu)",
			Command:  fmt.Sprintf(`sudo cp "%s" /usr/local/share/ca-certificates/internal-root-ca.crt && sudo update-ca-certificates`, absPath),
		},
		{
			Platform: "Linux (RHEL / CentOS / Fedora / Rocky)",
			Command:  fmt.Sprintf(`sudo cp "%s" /etc/pki/ca-trust/source/anchors/internal-root-ca.crt && sudo update-ca-trust`, absPath),
		},
		{
			Platform: "Google Chrome & Microsoft Edge (Windows)",
			Command:  "Chrome and Edge use the Windows Certificate Store automatically once installed into 'ROOT'.",
		},
		{
			Platform: "Mozilla Firefox (All OSes)",
			Command:  `In Firefox address bar type "about:config", set "security.enterprise_roots.enabled" = true, or import via Settings -> Privacy & Security -> Certificates -> View Certificates -> Authorities -> Import.`,
		},
	}
}

// ConfigureFirefoxProfiles locates Firefox profiles on the current user's system
// and enables "security.enterprise_roots.enabled" in user.js.
func ConfigureFirefoxProfiles(profilesDir string) (int, error) {
	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		return 0, nil
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return 0, err
	}

	configuredCount := 0
	targetPref := `user_pref("security.enterprise_roots.enabled", true);`

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profilePath := filepath.Join(profilesDir, entry.Name())
		userJSPath := filepath.Join(profilePath, "user.js")

		// Read existing content
		var content []byte
		if data, err := os.ReadFile(userJSPath); err == nil {
			content = data
		}

		// Check if preference already present
		if strings.Contains(string(content), "security.enterprise_roots.enabled") {
			configuredCount++
			continue
		}

		// Append preference
		newContent := string(content)
		if len(newContent) > 0 && !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		newContent += targetPref + "\n"

		if err := os.WriteFile(userJSPath, []byte(newContent), 0644); err == nil {
			configuredCount++
		}
	}

	return configuredCount, nil
}

// WriteFirefoxEnterprisePolicy writes a policies.json file into target directory.
func WriteFirefoxEnterprisePolicy(policyDir, certPath string) error {
	if err := os.MkdirAll(policyDir, 0755); err != nil {
		return err
	}

	policyPath := filepath.Join(policyDir, "policies.json")

	var policy FirefoxPolicy
	policy.Policies.ImportEnterpriseRoots = true
	if certPath != "" {
		absPath, err := filepath.Abs(certPath)
		if err == nil {
			policy.Policies.Certificates = &struct {
				Install []string `json:"Install,omitempty"`
			}{
				Install: []string{absPath},
			}
		}
	}

	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(policyPath, data, 0644)
}

// ParseCACert extracts an x509.Certificate from DER or PEM bytes.
func ParseCACert(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

