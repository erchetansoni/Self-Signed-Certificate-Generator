//go:build !windows && !linux

// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package trust

// InstallRootCA provides fallback and instructions for other operating systems (e.g. macOS, BSD).
func InstallRootCA(certDER []byte, certPEM []byte, certPath string, opts InstallOptions) (*InstallReport, error) {
	report := &InstallReport{
		ManualCommands: GenerateManualInstructions(certPath),
	}

	report.OSInstalled = false
	report.OSMessage = "Automatic installation not supported on this platform. Please run the manual command below."
	report.ChromeStatus = "Follow OS keychain/store instructions."
	report.EdgeStatus = "Follow OS keychain/store instructions."
	report.FirefoxInstalled = false
	report.FirefoxMessage = "Import manually via Firefox Certificate Manager."

	return report, nil
}

