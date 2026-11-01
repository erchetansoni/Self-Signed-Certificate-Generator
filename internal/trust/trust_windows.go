//go:build windows

// Copyright (c) 2026 Er. Chetan Soni (https://ErChetanSoni.github.io/)
// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial

package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	CERT_STORE_PROV_SYSTEM_W        = 10
	CERT_SYSTEM_STORE_CURRENT_USER  = 0x00010000
	CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
	CERT_STORE_ADD_REPLACE_EXISTING = 3
	X509_ASN_ENCODING               = 0x00000001
	PKCS_7_ASN_ENCODING             = 0x00010000
)

// InstallRootCA performs native, child-process-free installation into Windows certificate stores
// and configures browser trust for Chrome, Edge, and Firefox.
func InstallRootCA(certDER []byte, certPEM []byte, certPath string, opts InstallOptions) (*InstallReport, error) {
	report := &InstallReport{
		ManualCommands: GenerateManualInstructions(certPath),
	}

	if opts.InstallOS {
		// 1. Create native Windows Certificate Context
		certCtx, err := syscall.CertCreateCertificateContext(
			X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,
			&certDER[0],
			uint32(len(certDER)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create Windows certificate context: %w", err)
		}
		defer syscall.CertFreeCertificateContext(certCtx)

		storeNamePtr, err := syscall.UTF16PtrFromString("Root")
		if err != nil {
			return nil, err
		}

		// 2. Install into CurrentUser\Root (standard user store, trusted by Windows, Chrome, and Edge)
		hUserStore, err := syscall.CertOpenStore(
			CERT_STORE_PROV_SYSTEM_W,
			0,
			0,
			CERT_SYSTEM_STORE_CURRENT_USER,
			uintptr(unsafe.Pointer(storeNamePtr)),
		)
		if err != nil {
			report.OSMessage = fmt.Sprintf("Failed to open CurrentUser Root store: %v", err)
		} else {
			defer syscall.CertCloseStore(hUserStore, 0)
			err = syscall.CertAddCertificateContextToStore(
				hUserStore,
				certCtx,
				CERT_STORE_ADD_REPLACE_EXISTING,
				nil,
			)
			if err != nil {
				report.OSMessage = fmt.Sprintf("Failed to add to CurrentUser Root store: %v", err)
			} else {
				report.OSInstalled = true
				report.OSMessage = "Installed into Windows 'Trusted Root Certification Authorities' (CurrentUser\\Root)"
			}
		}

		// 3. Attempt installation into LocalMachine\Root (succeeds if running with Administrator privileges on Windows Server / Desktop)
		hLMStore, errLM := syscall.CertOpenStore(
			CERT_STORE_PROV_SYSTEM_W,
			0,
			0,
			CERT_SYSTEM_STORE_LOCAL_MACHINE,
			uintptr(unsafe.Pointer(storeNamePtr)),
		)
		if errLM == nil {
			err = syscall.CertAddCertificateContextToStore(
				hLMStore,
				certCtx,
				CERT_STORE_ADD_REPLACE_EXISTING,
				nil,
			)
			if err == nil {
				report.OSMessage += " and (LocalMachine\\Root)"
			}
			syscall.CertCloseStore(hLMStore, 0)
		}
	}

	if opts.InstallBrowsers {
		// Chrome and Edge on Windows use the Windows CryptoAPI Root store automatically
		if report.OSInstalled {
			report.ChromeStatus = "Trusted automatically via Windows Root Certificate Store"
			report.EdgeStatus = "Trusted automatically via Windows Root Certificate Store"
		} else {
			report.ChromeStatus = "Requires Windows Root store installation or manual import (chrome://settings/certificates)"
			report.EdgeStatus = "Requires Windows Root store installation or manual import (edge://settings/certificates)"
		}

		// Firefox configuration
		firefoxConfigured := false
		var firefoxDetails []string

		// A. Configure Firefox user profiles with security.enterprise_roots.enabled
		appData := os.Getenv("APPDATA")
		if appData != "" {
			ffProfilesDir := filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
			if count, err := ConfigureFirefoxProfiles(ffProfilesDir); err == nil && count > 0 {
				firefoxConfigured = true
				firefoxDetails = append(firefoxDetails, fmt.Sprintf("configured %d Firefox profile(s) with 'security.enterprise_roots.enabled=true'", count))
			}
		}

		// B. Configure Firefox enterprise policies if installation directories are found
		candidateDirs := []string{
			`C:\Program Files\Mozilla Firefox\distribution`,
			`C:\Program Files (x86)\Mozilla Firefox\distribution`,
			filepath.Join(os.Getenv("LOCALAPPDATA"), "Mozilla Firefox", "distribution"),
		}
		for _, dir := range candidateDirs {
			if parent := filepath.Dir(dir); fileOrDirExists(parent) {
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