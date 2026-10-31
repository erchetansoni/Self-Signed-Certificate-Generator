//go:build linux

package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// InstallRootCA performs Linux system and browser trust store installation.
func InstallRootCA(certDER []byte, certPEM []byte, certPath string, opts InstallOptions) (*InstallReport, error) {
	report := &InstallReport{
		ManualCommands: GenerateManualInstructions(certPath),
	}

	if opts.InstallOS {
		installed := false
		var installMsg string

		// Debian / Ubuntu: /usr/local/share/ca-certificates/
		debianDir := "/usr/local/share/ca-certificates"
		if fileOrDirExists(debianDir) {
			destPath := filepath.Join(debianDir, "internal-root-ca.crt")
			if err := os.WriteFile(destPath, certPEM, 0644); err == nil {
				installed = true
				installMsg = fmt.Sprintf("Copied to %s. Run 'sudo update-ca-certificates' to finalize trust store cache.", destPath)
			} else {
				installMsg = fmt.Sprintf("Permission denied writing to %s. Run manual command with sudo.", destPath)
			}
		}

		// RHEL / CentOS / Fedora: /etc/pki/ca-trust/source/anchors/
		rhelDir := "/etc/pki/ca-trust/source/anchors"
		if !installed && fileOrDirExists(rhelDir) {
			destPath := filepath.Join(rhelDir, "internal-root-ca.crt")
			if err := os.WriteFile(destPath, certPEM, 0644); err == nil {
				installed = true
				installMsg = fmt.Sprintf("Copied to %s. Run 'sudo update-ca-trust' to finalize trust store cache.", destPath)
			} else {
				installMsg = fmt.Sprintf("Permission denied writing to %s. Run manual command with sudo.", destPath)
			}
		}

		if installed {
			report.OSInstalled = true
			report.OSMessage = installMsg
		} else {
			report.OSInstalled = false
			report.OSMessage = installMsg
			if report.OSMessage == "" {
				report.OSMessage = "System CA anchor directory not found. Use manual copy-paste instructions."
			}
		}
	}

	if opts.InstallBrowsers {
		// Chrome / Chromium on Linux inherit system CA store
		if report.OSInstalled {
			report.ChromeStatus = "Trusted via system CA store after running update-ca-certificates / update-ca-trust"
			report.EdgeStatus = "Trusted via system CA store after running update-ca-certificates / update-ca-trust"
		} else {
			report.ChromeStatus = "Requires system trust store update or manual import via chrome://settings/certificates"
			report.EdgeStatus = "Requires system trust store update or manual import via edge://settings/certificates"
		}

		// Firefox on Linux
		homeDir, err := os.UserHomeDir()
		firefoxConfigured := false
		var firefoxDetails []string

		if err == nil {
			ffProfilesDir := filepath.Join(homeDir, ".mozilla", "firefox")
			if count, err := ConfigureFirefoxProfiles(ffProfilesDir); err == nil && count > 0 {
				firefoxConfigured = true
				firefoxDetails = append(firefoxDetails, fmt.Sprintf("configured %d Firefox profile(s) with 'security.enterprise_roots.enabled=true'", count))
			}
		}

		// Check system-wide Firefox distribution policy
		systemPolicyDirs := []string{
			"/etc/firefox/policies",
			"/usr/lib/firefox/distribution",
			"/usr/lib64/firefox/distribution",
		}
		for _, dir := range systemPolicyDirs {
			if fileOrDirExists(dir) {
				if err := WriteFirefoxEnterprisePolicy(dir, certPath); err == nil {
					firefoxConfigured = true
					firefoxDetails = append(firefoxDetails, fmt.Sprintf("created enterprise policy in %s", dir))
					break
				}
			}
		}

		if firefoxConfigured {
			report.FirefoxInstalled = true
			report.FirefoxMessage = fmt.Sprintf("Active (%s)", strings.Join(firefoxDetails, "; "))
		} else {
			report.FirefoxInstalled = false
			report.FirefoxMessage = "Manual action required (see copy-paste instructions below)"
		}
	}

	return report, nil
}

func fileOrDirExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

