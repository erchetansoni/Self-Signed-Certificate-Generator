# Self-Signed Certificate Generator (TUI/CLI)

> **Production-Grade, Air-Gapped, EDR-Safe PKI & X.509 Certificate Generator**  
> Developed by **Er. Chetan Soni** • [https://ErChetanSoni.github.io/](https://ErChetanSoni.github.io/)

[![Author](https://img.shields.io/badge/Author-Er.%20Chetan%20Soni-blue.svg)](https://ErChetanSoni.github.io/)
[![Website](https://img.shields.io/badge/Website-ErChetanSoni.github.io-00D7D7.svg)](https://ErChetanSoni.github.io/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3%20%2F%20Commercial-brightgreen.svg)](#10-license--dual-licensing)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://golang.org)
[![Security](https://img.shields.io/badge/EDR--Safe-Zero--Socket%20%7C%20Zero--Proc-brightgreen.svg)](#3-edr--antivirus-safety-model)
[![Air-Gap](https://img.shields.io/badge/Air--Gap-100%25%20Offline-blue.svg)](#1-architectural-highlights)
[![PKI](https://img.shields.io/badge/PKI-Root%20CA%20%2B%20Signed%20Leaf-purple.svg)](#2-root-ca--pki-hierarchy-architecture)

**Self-Signed Certificate Generator** is a cross-platform, single-binary Terminal User Interface (TUI) and CLI application in **Go (Golang)** that generates complete X.509 PKI hierarchies (Root CA + signed Leaf certificates), reuses existing Root CAs, and provides automated trust store installation across Windows, Linux, Chrome, Edge, and Firefox.

---

## 1. Architectural Highlights

### Zero External Runtime Dependencies
- **No external binaries:** Eliminates dependencies on OpenSSL, Python, Node.js, or Java.
- **Pure Go cryptography:** Built exclusively on Go's native standard library (`crypto/x509`, `crypto/rsa`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `encoding/pem`) with pure-Go PKCS#12 bundle support (`software.sslmate.com/src/go-pkcs12`).
- **Static linking:** Compiled with `CGO_ENABLED=0` and `-trimpath`. No dynamic C libraries (`libc`, `glibc`, `musl`) required.

### Air-Gap Compatibility
- **100% Offline execution:** Performs zero network operations.
- **Zero telemetry or analytics:** Never communicates with remote endpoints.
- **No internal sockets:** Does not bind to local ports or loopback (`127.0.0.1`, `::1`).

---

## 2. Root CA & PKI Hierarchy Architecture

When generating development or internal certificates, standalone self-signed certificates cause browser security warnings ("Your connection is not private", `NET::ERR_CERT_AUTHORITY_INVALID`). 

**Self-Signed Certificate Generator solves this by supporting two production PKI workflows:**

### Workflow A: Generate a NEW Root CA + Signed Leaf Certificate
1. **Dedicated Root Certificate Authority (Root CA):**
   - Self-signed, configurable validity in **Years** (default: `10 years`, e.g. 5, 10, 20, 30 years).
   - `IsCA: true`, `BasicConstraintsValid: true`, `KeyUsage: CertSign | CRLSign | DigitalSignature`.
   - Output files: `rootCA.pem` / `rootCA.crt` and `rootCA-key.pem` / `rootCA.key`.
2. **Server & Client Leaf Certificate:**
   - Cryptographically **signed by the Root CA**.
   - Includes custom SANs (DNS names, IPv4, IPv6) and Common Name.
   - Output files: `cert.pem` / `cert.crt` and `key.pem` / `key.key`.
3. **Full Certificate Chain & PKCS#12 Bundle:**
   - `chain.pem` / `chain.crt`: Concatenated Leaf + Root CA for Nginx, Apache, Caddy, Envoy.
   - `bundle.p12` / `bundle.pfx`: Complete PKCS#12 bundle containing Leaf key, Leaf cert, and Root CA cert for Windows CertMgr, IIS, and Java keytool.

### Workflow B: Sign using an EXISTING Root CA
If you already generated a Root CA previously (or have a company/team Root CA):
- **Auto-Detection:** Place `rootCA.pem` and `rootCA-key.pem` (or `.crt` / `.key`) in the current folder, executable folder, or `./certs/`. The generator will automatically detect it upon launch!
- **Custom Path Input:** Alternatively, specify any custom path in the TUI form or via CLI flags (`-ca-cert` and `-ca-key`).
- **Zero Retrusting Needed:** Since your existing Root CA is already installed and trusted in your OS/browsers, any new leaf certificates issued are **instantly trusted without needing to re-install anything**!

### Output Folder Files Summary

```
output_dir/
├── rootCA.pem      (or rootCA.crt)   <── ROOT CA CERTIFICATE (To be installed into OS & Browsers)
├── rootCA-key.pem  (or rootCA.key)   <── ROOT CA PRIVATE KEY (Strict 0600 permissions)
├── cert.pem        (or cert.crt)     <── LEAF CERTIFICATE (Signed cryptographically by Root CA)
├── key.pem         (or key.key)      <── LEAF PRIVATE KEY (Strict 0600 permissions)
├── chain.pem       (or chain.crt)    <── FULL CHAIN (Concatenated Leaf + Root CA for Nginx/Caddy)
└── bundle.p12      (or bundle.pfx)   <── PKCS#12 BUNDLE (Leaf Key + Leaf Cert + Root CA Chain)
```

---

## 3. EDR & Antivirus Safety Model

Enterprise security sensors (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black) often flag administrative certificate utilities due to behavioral heuristics. Self-Signed Certificate Generator is engineered to eliminate false positives:
- **Zero Socket Binding:** Never creates listening TCP/UDP sockets (no `net.Listen`).
- **Zero Child Process Invocations:** No `exec.Command`, `cmd.exe`, `powershell.exe`, or `certutil.exe` execution. All Windows store interactions use sanctioned `crypt32.dll` CryptoAPI calls.
- **Unpacked Binary:** UPX and third-party binary packers are explicitly forbidden to prevent high-entropy detections.
- **Windows PE Resource Manifest:** Embedded with authentic Windows PE version tables and `asInvoker` execution-level manifests via `go-winres`.
- **Reproducible Path Trimming:** Built with `-trimpath` to eliminate local file paths from executable debug headers.

---

## 4. Automated OS & Browser Trust Store Integration

CertGen provides child-process-free, native installation of the Root CA into OS and browser trust stores:

### Windows (10, 11, Windows Server 2016 / 2019 / 2022 / 2025 / 2026)
- **Zero-Subprocess Windows CryptoAPI:** Calls native Windows `crypt32.dll` via Go standard library `syscall` (`CertOpenStore`, `CertCreateCertificateContext`, `CertAddCertificateContextToStore`, `CertCloseStore`).
- Installs into `CurrentUser\Root` (no admin rights needed) and `LocalMachine\Root` (if running elevated).
- **Google Chrome & Microsoft Edge:** On Windows, Chrome and Edge query the Windows CryptoAPI Root store directly. Once the Root CA is added, Chrome and Edge trust the certificate with **no warnings**.

### Mozilla Firefox
- Automatically scans user profiles in `%APPDATA%\Mozilla\Firefox\Profiles\` (Windows) or `~/.mozilla/firefox/` (Linux) and enables `user_pref("security.enterprise_roots.enabled", true);` in `user.js`.
- Writes enterprise policy `distribution/policies.json` to Firefox installation directories to trust the Root CA globally.

### Linux (Ubuntu, Debian, RHEL, CentOS, Fedora, Rocky)
- Automatically copies `rootCA.crt` to `/usr/local/share/ca-certificates/` (Debian/Ubuntu) or `/etc/pki/ca-trust/source/anchors/` (RHEL/Fedora) if running with appropriate permissions.
- Configures Firefox profile `user.js` in `~/.mozilla/firefox/` to enable enterprise roots.

---

## 5. How to Run the Binaries

The compiled executables are located in the `dist/` directory:
- `dist/certgen-windows-amd64.exe` (Windows PE executable)
- `dist/certgen-linux-amd64` (Linux ELF 64-bit static executable)

### A. Running on Windows (`certgen-windows-amd64.exe`)
Run directly from PowerShell, Windows Terminal, or Command Prompt:

```powershell
.\dist\certgen-windows-amd64.exe
```

### B. Running on Linux (`certgen-linux-amd64`)
Because `certgen-linux-amd64` was compiled with `CGO_ENABLED=0` (statically linked), it has **zero external library dependencies** (`no libc/glibc/musl requirements`). It runs on **any 64-bit Linux distribution** (Ubuntu, Debian, CentOS, RHEL, Fedora, Rocky, Alpine, Arch, Amazon Linux, etc.).

#### Method 1: On a Remote / Dedicated Linux Machine
1. **Transfer the binary** to your Linux server (via `scp`, SFTP, or USB):
   ```bash
   scp dist/certgen-linux-amd64 user@your-linux-server:/home/user/
   ```
2. **SSH into the server**:
   ```bash
   ssh user@your-linux-server
   ```
3. **Grant execute permission**:
   ```bash
   chmod +x certgen-linux-amd64
   ```
4. **Execute**:
   ```bash
   ./certgen-linux-amd64
   ```

#### Method 2: On Windows using WSL (Windows Subsystem for Linux)
If you are on Windows and want to run the Linux binary locally:
```powershell
wsl ./dist/certgen-linux-amd64
```

#### Method 3: Inside a Docker Container
You can run the Linux binary inside an isolated container directly from your Windows host:
```powershell
docker run -it --rm -v "${PWD}:/app" -w /app ubuntu ./dist/certgen-linux-amd64
```

---

## 6. Usage & Modes

### Interactive TUI Mode (Default)
Simply run the binary without arguments in any terminal:
```bash
./dist/certgen-windows-amd64.exe
# or on Linux / WSL:
./dist/certgen-linux-amd64
```

The interactive terminal form guides you through:
1. **Certificate Hierarchy / Role:**
   - `Sign with Detected Root CA` (if `rootCA.pem` is found in the folder)
   - `Generate NEW Root CA + Signed Leaf Certificate (Recommended)`
   - `Sign with an Existing Root CA (Specify custom file path)`
   - `Root / Intermediate CA Only`
   - `Standalone Self-Signed Leaf Only`
2. **Key Algorithm & Size:** Choose ECDSA (P-256 / P-384) or RSA (2048 / 4096-bit).
3. **Subject Identity:** Common Name (CN), Organization, Country.
4. **SANs:** Comma-separated DNS names and IP addresses.
5. **Validity Durations:**
   - **Root CA Validity Duration (Years):** Explicit prompt for how many years the Root CA should be valid [Default: `10 years`, e.g. 5, 10, 20, 30].
   - **Leaf Certificate Validity Duration (Days):** Number of days for the server/client cert [Default: `365 days` / 1 year].
6. **Output Configuration:** Target folder, naming scheme (`.pem` or `.crt`), and PKCS#12 bundle.
7. **Trust Store Installation:**
   - `Install Root CA into OS Trust Store?` (Yes/No)
   - `Install Root CA for Browsers (Chrome, Edge, Firefox)?` (Yes/No)

---

### Non-Interactive / CLI Mode Examples

#### Example 1: Generate a New Root CA + Signed Leaf Certificate
```bash
./dist/certgen-windows-amd64.exe -non-interactive \
  -role ca-leaf \
  -cn "app.internal" \
  -ca-cn "Internal Development Root CA" \
  -ca-years 10 \
  -san-dns "app.internal,*.app.internal,localhost" \
  -san-ip "127.0.0.1,10.0.0.1" \
  -key-type "ecdsa-p256" \
  -days 365 \
  -out-dir "./certs" \
  -p12 \
  -p12-pass "Secret123!" \
  -install-os \
  -install-browser
```

#### Example 2: Sign a New Certificate with an Existing Root CA
```bash
./dist/certgen-windows-amd64.exe -non-interactive \
  -role existing-ca \
  -ca-cert "./certs/rootCA.pem" \
  -ca-key "./certs/rootCA-key.pem" \
  -cn "billing.internal" \
  -san-dns "billing.internal,localhost" \
  -days 365 \
  -out-dir "./billing-certs"
```

---

### CLI Flags Reference

| Flag | Default | Description |
|---|---|---|
| `-role` | `ca-leaf` | Certificate mode: `ca-leaf` (New CA + Leaf), `existing-ca` (Sign with Existing CA), `ca` (CA only), `leaf` (self-signed leaf) |
| `-cn` | `""` | Common Name (CN) [Mandatory in non-interactive mode] |
| `-ca-cn` | `"<CN> Root CA"` | Root CA Common Name (when generating a new CA) |
| `-ca-years` | `10` | **Root CA validity duration in YEARS** (default: 10 years, e.g. 5, 10, 20, 30) |
| `-ca-days` | `0` | Root CA validity duration in days (overrides `-ca-years` if specified) |
| `-ca-cert` | `""` | **Path to existing Root CA certificate** (e.g. `./rootCA.pem`) |
| `-ca-key` | `""` | **Path to existing Root CA private key** (e.g. `./rootCA-key.pem`) |
| `-ca-pass` | `""` | Passphrase for existing Root CA private key (if encrypted) |
| `-key-type` | `ecdsa-p256` | Key type: `ecdsa-p256`, `ecdsa-p384`, `rsa-2048`, `rsa-4096` |
| `-o` | `Internal / Dev` | Organization (O) |
| `-ou` | `""` | Organizational Unit (OU) |
| `-c` | `US` | 2-letter ISO 3166-1 country code |
| `-san-dns` | `""` | Comma-separated DNS SANs |
| `-san-ip` | `""` | Comma-separated IP SANs |
| `-days` | `365` | **Leaf certificate validity duration in DAYS** (default: 365 days / 1 year) |
| `-out-dir` | `./` | Output directory for all generated files |
| `-ca-name` | `rootCA.pem` | Root CA certificate filename |
| `-ca-key-name` | `rootCA-key.pem` | Root CA private key filename |
| `-cert-name` | `cert.pem` | Leaf certificate filename |
| `-key-name` | `key.pem` | Leaf private key filename |
| `-chain-name`| `chain.pem` | Full chain filename |
| `-p12` | `false` | Enable PKCS#12 bundle generation |
| `-p12-name` | `bundle.p12` | PKCS#12 bundle filename |
| `-p12-pass` | `""` | Export password for PKCS#12 bundle |
| `-install-os` | `false` | Install Root CA into OS / system trust store |
| `-install-browser`| `false`| Install Root CA for Chrome, Edge, and Firefox |
| `-non-interactive`| `false` | Run in non-interactive CLI mode |
| `-version` | `false` | Display version, author, and licensing metadata |

---

## 7. Manual Cross-Platform Trust Commands (Quick Reference)

If you distribute `rootCA.pem` / `rootCA.crt` to other machines, use these native platform commands:

| Platform / Browser | Command |
|---|---|
| **Windows CMD / PowerShell (Admin)** | `certutil -addstore -f "ROOT" "C:\path\to\rootCA.pem"` |
| **Windows PowerShell (Current User)** | `Import-Certificate -FilePath "C:\path\to\rootCA.pem" -CertStoreLocation Cert:\CurrentUser\Root` |
| **Linux (Ubuntu / Debian)** | `sudo cp rootCA.pem /usr/local/share/ca-certificates/internal-root-ca.crt && sudo update-ca-certificates` |
| **Linux (RHEL / CentOS / Fedora / Rocky)** | `sudo cp rootCA.pem /etc/pki/ca-trust/source/anchors/internal-root-ca.crt && sudo update-ca-trust` |
| **Google Chrome & Microsoft Edge** | Uses OS trust store automatically once added to Windows `ROOT` or Linux `ca-certificates`. |
| **Mozilla Firefox (All OSes)** | In address bar type `about:config`, set `security.enterprise_roots.enabled` to `true`. |

---

## 8. Author & Personal Branding

Developed and maintained by **Er. Chetan Soni**:
- **Website & Portfolio:** [https://ErChetanSoni.github.io/](https://ErChetanSoni.github.io/)
- **GitHub:** [@ErChetanSoni](https://github.com/ErChetanSoni)

---

## 9. Building from Source

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

All build scripts compile Windows PE resource manifests (`winres.json`), build statically linked binaries with `CGO_ENABLED=0` and `-trimpath -ldflags="-s -w"`, and output artifacts to `dist/`.

---

## 10. License & Dual-Licensing

This project is dual-licensed under:
1. **GNU General Public License v3.0 (GPLv3)** for open-source and personal use.
2. **Commercial License** for enterprise customers, closed-source integrations, or organizations requiring proprietary terms and support without copyleft requirements.

See [LICENSE](LICENSE) for the full GPLv3 text and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md) for commercial licensing details.

For commercial inquiries, licensing, and enterprise support:
Visit [https://ErChetanSoni.github.io/](https://ErChetanSoni.github.io/)
