package trust

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateManualInstructions(t *testing.T) {
	instructions := GenerateManualInstructions("/path/to/rootCA.crt")
	if len(instructions) == 0 {
		t.Fatalf("Expected manual instructions, got none")
	}

	hasWindows := false
	hasLinux := false
	hasFirefox := false

	for _, inst := range instructions {
		if strings.Contains(inst.Platform, "Windows") {
			hasWindows = true
		}
		if strings.Contains(inst.Platform, "Linux") {
			hasLinux = true
		}
		if strings.Contains(inst.Platform, "Firefox") {
			hasFirefox = true
		}
	}

	if !hasWindows || !hasLinux || !hasFirefox {
		t.Errorf("Missing platform instructions: Windows=%v, Linux=%v, Firefox=%v", hasWindows, hasLinux, hasFirefox)
	}
}

func TestConfigureFirefoxProfiles(t *testing.T) {
	tempProfilesDir := t.TempDir()

	// Create fake profiles
	prof1 := filepath.Join(tempProfilesDir, "abc.default-release")
	prof2 := filepath.Join(tempProfilesDir, "xyz.default")
	if err := os.MkdirAll(prof1, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prof2, 0755); err != nil {
		t.Fatal(err)
	}

	// Run configure
	count, err := ConfigureFirefoxProfiles(tempProfilesDir)
	if err != nil {
		t.Fatalf("ConfigureFirefoxProfiles failed: %v", err)
	}
	if count != 2 {
		t.Errorf("Expected 2 configured profiles, got %d", count)
	}

	// Verify user.js exists in prof1 and contains the preference
	userJSPath := filepath.Join(prof1, "user.js")
	content, err := os.ReadFile(userJSPath)
	if err != nil {
		t.Fatalf("Failed to read user.js: %v", err)
	}
	if !strings.Contains(string(content), `user_pref("security.enterprise_roots.enabled", true);`) {
		t.Errorf("user.js missing target preference, got: %s", string(content))
	}

	// Re-running shouldn't duplicate or error
	count2, err := ConfigureFirefoxProfiles(tempProfilesDir)
	if err != nil {
		t.Fatalf("Second ConfigureFirefoxProfiles failed: %v", err)
	}
	if count2 != 2 {
		t.Errorf("Expected 2 on rerun, got %d", count2)
	}
}

func TestWriteFirefoxEnterprisePolicy(t *testing.T) {
	tempDir := t.TempDir()
	policyDir := filepath.Join(tempDir, "distribution")

	err := WriteFirefoxEnterprisePolicy(policyDir, "/tmp/ca.crt")
	if err != nil {
		t.Fatalf("WriteFirefoxEnterprisePolicy failed: %v", err)
	}

	policyPath := filepath.Join(policyDir, "policies.json")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatalf("Failed to read policies.json: %v", err)
	}

	if !strings.Contains(string(data), `"ImportEnterpriseRoots": true`) {
		t.Errorf("policies.json missing ImportEnterpriseRoots: %s", string(data))
	}
}

