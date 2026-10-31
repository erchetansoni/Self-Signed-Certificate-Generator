# CertGen: Air-Gapped, EDR-Safe Self-Signed Certificate Generator (TUI)
# CertGen: Air-Gapped, EDR-Safe PKI & Certificate Authority Generator (TUI)

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Security](https://img.shields.io/badge/EDR--Safe-Zero--Socket%20%7C%20Zero--Proc-brightgreen.svg)](#edr--antivirus-safety-model)
[![Air-Gap](https://img.shields.io/badge/Air--Gap-100%25%20Offline-blue.svg)](#air-gap-compatibility)
[![PKI](https://img.shields.io/badge/PKI-Root%20CA%20%2B%20Signed%20Leaf-purple.svg)](#root-ca--pki-hierarchy)

A single-binary, cross-platform Terminal User Interface (TUI) and CLI application written in **Go** that generates standards-compliant self-signed X.509 certificates and private keys.
A single-binary, cross-platform Terminal User Interface (TUI) and CLI application written in **Go** that generates complete, standards-compliant X.509 PKI hierarchies (Root CA + signed Leaf certificates), private keys, and automated OS & browser trust integration.

---

## 1. Architectural Highlights
## 1. Root CA & PKI Hierarchy Architecture

### Zero External Runtime Dependencies
- **No external binaries:** Eliminates dependencies on OpenSSL, Python, Node.js, or Java.
- **Pure Go cryptography:** Built exclusively on Go's native standard library (`crypto/x509`, `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `encoding/pem`) with pure-Go PKCS#12 bundle support (`software.sslmate.com/src/go-pkcs12`).
- **Static linking:** Compiled with `CGO_ENABLED=0` and `-trimpath`. No dynamic C libraries (`libc`, `glibc`, `musl`) required.
When generating development or internal certificates, standalone self-signed certificates cause browser security warnings ("Your connection is not private", `NET::ERR_CERT_AUTHORITY_INVALID`). 

### Air-Gap Compatibility
- **100% Offline execution:** Performs zero network operations.
- **Zero telemetry or analytics:** Never communicates with remote endpoints.
- **No internal sockets:** Does not bind to local ports or loopback (`127.0.0.1`, `::1`).
**CertGen solves this by generating a full PKI hierarchy:**
1. **Dedicated Root Certificate Authority (Root CA):**
   - Self-signed, 10-year validity (`3650 days`), `IsCA: true`, `KeyUsage: CertSign | CRLSign | DigitalSignature`.
   - Output files: `rootCA.pem` / `rootCA.crt` and `rootCA-key.pem` / `rootCA.key`.
2. **Server & Client Leaf Certificate:**
   - Cryptographically **signed by the Root CA**.
   - Includes custom SANs (DNS names, IPv4, IPv6) and Common Name.
   - Output files: `cert.pem` / `cert.crt` and `key.pem` / `key.key`.
3. **Full Certificate Chain & PKCS#12 Bundle:**
   - `chain.pem` / `chain.crt`: Concatenated Leaf + Root CA for nginx, apache, caddy, envoy.
   - `bundle.p12` / `bundle.pfx`: Complete PKCS#12 bundle containing Leaf key, Leaf cert, and Root CA cert for Windows CertMgr, IIS, and Java keytool.

### EDR & Antivirus Safety Model
Enterprise security sensors (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black) often flag utilities due to behavioral heuristics. CertGen is engineered to eliminate false positives:
- **Zero Socket Binding:** Never creates listening TCP/UDP sockets.
- **Zero Child Process Invocations:** No `exec.Command`, `cmd.exe`, `powershell`, or `xdg-open` calls.
- **Unpacked Binary:** UPX and third-party binary packers are explicitly forbidden to prevent high-entropy detections.
- **Windows PE Resource Manifest:** Embedded with authentic Windows PE version tables and `asInvoker` execution-level manifests via `go-winres`.
- **Reproducible Path Trimming:** Built with `-trimpath` to eliminate local file paths from executable debug headers.
---

## 2. Automated OS & Browser Trust Store Integration

CertGen provides child-process-free, native installation of the Root CA into OS and browser trust stores:

### Windows (10, 11, Windows Server 2016 / 2019 / 2022 / 2025 / 2026)
- **Zero-Subprocess Windows CryptoAPI:** Calls native Windows `crypt32.dll` via Go standard library `syscall` (`CertOpenStore`, `CertCreateCertificateContext`, `CertAddCertificateContextToStore`).
- Installs into `CurrentUser\Root` (no admin rights needed) and `LocalMachine\Root` (if running elevated).
- **Google Chrome & Microsoft Edge:** On Windows, Chrome and Edge use the Windows CryptoAPI Root store automatically. As soon as the Root CA is added, Chrome and Edge trust the certificate with **no warnings**.

### Mozilla Firefox
- Automatically scans user profiles in `%APPDATA%\Mozilla\Firefox\Profiles\` and enables `user_pref("security.enterprise_roots.enabled", true);` in `user.js`.
- Writes enterprise policy `distribution/policies.json` to Firefox installation directories to trust the Root CA globally.

### Linux (Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky)
- Automatically copies `rootCA.crt` to `/usr/local/share/ca-certificates/` (Debian/Ubuntu) or `/etc/pki/ca-trust/source/anchors/` (RHEL/Fedora) if running with appropriate permissions, or provides the exact 1-line copy-paste commands.
- Configures Firefox profile `user.js` in `~/.mozilla/firefox/` to enable enterprise roots.

---

## 2. Cryptographic Specifications
## 3. EDR & Antivirus Safety Model

- **Certificate Roles:**
  - **Leaf (End-Entity):** `IsCA: false`, `BasicConstraintsValid: true`, `KeyUsage: DigitalSignature` (+ `KeyEncipherment` for RSA), `ExtKeyUsage: [ServerAuth, ClientAuth]`.
  - **Certificate Authority (CA):** `IsCA: true`, `BasicConstraintsValid: true`, `MaxPathLen: 1`, `KeyUsage: CertSign | CRLSign | DigitalSignature` (+ `KeyEncipherment` for RSA).
- **Key Algorithms:**
  - **ECDSA:** P-256 (default, high performance) or P-384 (Suite B / high security).
  - **RSA:** 2048-bit (standard compatibility) or 4096-bit (high security).
- **Serial Numbers:** Cryptographically secure 128-bit random integers (`crypto/rand`).
- **Key Identifiers:** RFC 5280 Section 4.2.1.2 Method (1) Subject Key Identifier (SHA-1 hash of public key bit string). For self-signed certificates, Authority Key Identifier matches SKID.
- **Clock Skew Tolerance:** Automatic 5-minute pre-dating of `NotBefore` to prevent validity issues across out-of-sync air-gapped nodes.
- **Formats:**
  - Certificates: PEM (`CERTIFICATE`)
  - Private Keys: Unencrypted PEM (default PKCS#8 `PRIVATE KEY` or traditional `RSA PRIVATE KEY` / `EC PRIVATE KEY`), written with strict `0600` permissions.
  - PKCS#12: Optional `.p12` / `.pfx` bundle with optional export password.
Enterprise security sensors (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) often flag administrative certificate utilities due to behavioral heuristics. CertGen is engineered to eliminate false positives:
- **Zero Socket Binding:** Never creates listening TCP/UDP sockets (no `net.Listen`).
- **Zero Child Process Invocations:** No `exec.Command`, `cmd.exe`, `powershell.exe`, or `certutil.exe` execution. All Windows store interactions use sanctioned `crypt32.dll` CryptoAPI calls.
- **Unpacked Binary:** UPX and third-party binary packers are explicitly forbidden to prevent high-entropy detections.
- **Windows PE Resource Manifest:** Embedded with authentic Windows PE version tables and `asInvoker` execution-level manifests via `go-winres`.
- **Reproducible Path Trimming:** Built with `-trimpath` to eliminate local file paths from executable debug headers.

---

## 3. Directory Layout
## 4. Directory Layout

```
.
├── cmd/
├── internal/
│   ├── cert/
│   │   ├── cert.go          # Core cryptographic engine and file persistence
│   │   └── cert_test.go     # Comprehensive crypto unit test suite
│   │   ├── cert.go          # Core cryptographic engine (PKI hierarchy, Root CA, Leaf)
│   │   └── cert_test.go     # Crypto test suite (KeyUsage, SANs, CA signatures)
│   ├── trust/
│   │   ├── trust.go         # Cross-platform trust store interfaces & Firefox config
│   │   ├── trust_windows.go # Native Windows CryptoAPI syscalls (crypt32.dll)
│   │   ├── trust_linux.go   # Linux ca-certificates & update-ca-trust anchors
│   │   ├── trust_other.go   # Fallbacks for macOS / BSD
│   │   └── trust_test.go    # Trust module tests
│   └── ui/
│       └── form.go          # Interactive terminal form using Charm Huh
│       └── form.go          # Interactive terminal form using Charm Huh & Lipgloss
├── winres/
│   ├── winres.json          # Windows PE metadata and execution manifest
│   ├── icon.png             # Application icon (high-res)
│   └── icon16.png           # Application icon (16x16)
├── dist/                    # Compiled release binaries
│   ├── certgen-windows-amd64.exe
│   └── certgen-linux-amd64
├── main.go                  # CLI entry point (TUI + Non-interactive flags)
├── main_test.go             # End-to-end integration test
├── build.ps1                # PowerShell build script for Windows
├── build.sh                 # Bash build script for Linux / macOS
├── Makefile                 # Standard Make build targets
├── go.mod
└── go.sum
```

---

## 4. Building from Source

### Prerequisites
- Go 1.22+ (stable release)

### Windows (PowerShell)
```powershell
.\build.ps1
```

### Linux / macOS (Bash)
```bash
chmod +x build.sh
./build.sh
```

### Using Make
```bash
make
```

All build scripts compile Windows PE resource manifests (`rsrc_windows_amd64.syso`), build statically linked binaries with `CGO_ENABLED=0` and `-trimpath -ldflags="-s -w"`, and output artifacts into `dist/`.

---

## 5. Usage

### Interactive TUI Mode (Default)
Simply run the executable in an interactive terminal:
Simply run the executable in your terminal:
```bash
./dist/certgen-windows-amd64.exe
# or on Linux:
./dist/certgen-linux-amd64
```
The application presents a terminal form powered by Charm Huh guiding you through:
1. **Certificate Role:** Leaf vs CA
2. **Key Type:** ECDSA P-256/P-384 or RSA 2048/4096
3. **Identity:** Common Name (CN), Organization (O), Organizational Unit (OU), Country (C)
4. **SANs:** Comma-separated DNS names and IP addresses
5. **Validity Duration:** Number of days (default: 365, max: 3650)
6. **Output Configuration:** Target folder, PEM/CRT naming scheme, optional PKCS#12 bundle.
The application presents an interactive form:
1. **Certificate Hierarchy / Role:** Select `Root CA + Signed Leaf Certificate (Recommended)`.
2. **Key Algorithm & Size:** Choose ECDSA (P-256 / P-384) or RSA (2048 / 4096-bit).
3. **Subject Identity:** Common Name (CN), Root CA Name, Organization, Country.
4. **SANs:** Comma-separated DNS names and IP addresses.
5. **Validity Duration:** Number of days.
6. **Output Configuration:** Output folder, naming scheme (`.pem` or `.crt`), and PKCS#12 bundle.
7. **Trust Store Installation:**
   - `Install Root CA into OS Trust Store?` (Yes/No)
   - `Install Root CA for Browsers (Chrome, Edge, Firefox)?` (Yes/No)

### Non-Interactive / Headless Mode
For CI/CD pipelines, container provisioning, or automated deployment scripts:
### Non-Interactive / CLI Mode
```bash
./certgen-linux-amd64 -non-interactive \
./dist/certgen-windows-amd64.exe -non-interactive \
  -role ca-leaf \
  -cn "app.internal" \
  -o "ACME Infrastructure" \
  -ca-cn "Internal Development Root CA" \
  -san-dns "app.internal,*.app.internal,localhost" \
  -san-ip "127.0.0.1,10.0.0.15" \
  -san-ip "127.0.0.1,10.0.0.1" \
  -key-type "ecdsa-p256" \
  -days 365 \
  -out-dir "./certs" \
  -p12 \
  -p12-pass "changeit"
  -p12-pass "Secret123!" \
  -install-os \
  -install-browser
```

#### CLI Flags Reference

| Flag | Default | Description |
|---|---|---|
| `-role` | `leaf` | Certificate role: `leaf` or `ca` |
| `-role` | `ca-leaf` | Certificate mode: `ca-leaf` (Root CA + Leaf), `ca` (CA only), `leaf` (self-signed leaf) |
| `-cn` | `""` | Common Name (CN) [Mandatory in non-interactive mode] |
| `-ca-cn` | `"<CN> Root CA"` | Root CA Common Name |
| `-ca-days` | `3650` | Root CA validity duration in days (default: 10 years) |
| `-key-type` | `ecdsa-p256` | Key type: `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096` |
| `-cn` | `""` | Common Name (CN) [Mandatory in non-interactive mode] |
| `-o` | `Internal / Dev` | Organization (O) |
| `-ou` | `""` | Organizational Unit (OU) |
| `-c` | `US` | 2-letter ISO 3166-1 country code |
| `-san-dns` | `""` | Comma-separated DNS SANs |
| `-san-ip` | `""` | Comma-separated IP SANs |
| `-days` | `365` | Validity duration in days (1 - 3650) |
| `-out-dir` | `./` | Destination directory for files |
| `-cert-name` | `cert.pem` | Certificate filename |
| `-key-name` | `key.pem` | Private key filename |
| `-days` | `365` | Validity duration for leaf certificate in days |
| `-out-dir` | `./` | Output directory for all generated files |
| `-ca-name` | `rootCA.pem` | Root CA certificate filename |
| `-ca-key-name` | `rootCA-key.pem` | Root CA private key filename |
| `-cert-name` | `cert.pem` | Leaf certificate filename |
| `-key-name` | `key.pem` | Leaf private key filename |
| `-chain-name`| `chain.pem` | Full chain filename |
| `-p12` | `false` | Enable PKCS#12 bundle generation |
| `-p12-name` | `cert.p12` | PKCS#12 bundle filename |
| `-p12-name` | `bundle.p12` | PKCS#12 bundle filename |
| `-p12-pass` | `""` | Export password for PKCS#12 bundle |
| `-key-format` | `pkcs8` | Private key format: `pkcs8` or `traditional` |
| `-non-interactive`| `false` | Force headless execution without TUI |
| `-version` | `false` | Display version and architecture metadata |
| `-install-os` | `false` | Install Root CA into OS / system trust store |
| `-install-browser`| `false`| Install Root CA for Chrome, Edge, and Firefox |
| `-non-interactive`| `false` | Run in non-interactive CLI mode |
| `-version` | `false` | Display version and build metadata |

---

## 6. Running Tests
## 6. Building from Source

Execute the full cryptographic test suite:
### Windows (PowerShell)
```powershell
.\build.ps1
```

### Linux / macOS (Bash)
```bash
go test -v ./...
./build.sh
```
Tests verify:
- DER/PEM parsing via `x509.ParseCertificate`
- 128-bit cryptographically secure serial numbers
- Subject Alternative Names (DNS names, IPv4, IPv6)
- RSA and ECDSA key pair validity and signature verification
- KeyUsages and ExtendedKeyUsages conformance
- Unencrypted PEM formatting and PKCS#8 parsing
- PKCS#12 encoding and decoding
- Strict POSIX file permissions (`0600` on key files)

### Using Make
```bash
make
```
All build scripts compile Windows PE resource manifests (`winres.json`), build statically linked binaries with `CGO_ENABLED=0` and `-trimpath -ldflags="-s -w"`, and output artifacts to `dist/`.
