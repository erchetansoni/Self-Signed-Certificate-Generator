# CertGen: Air-Gapped, EDR-Safe Self-Signed Certificate Generator (TUI)

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Security](https://img.shields.io/badge/EDR--Safe-Zero--Socket%20%7C%20Zero--Proc-brightgreen.svg)](#edr--antivirus-safety-model)
[![Air-Gap](https://img.shields.io/badge/Air--Gap-100%25%20Offline-blue.svg)](#air-gap-compatibility)

A single-binary, cross-platform Terminal User Interface (TUI) and CLI application written in **Go** that generates standards-compliant self-signed X.509 certificates and private keys.

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

### EDR & Antivirus Safety Model
Enterprise security sensors (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Carbon Black) often flag utilities due to behavioral heuristics. CertGen is engineered to eliminate false positives:
- **Zero Socket Binding:** Never creates listening TCP/UDP sockets.
- **Zero Child Process Invocations:** No `exec.Command`, `cmd.exe`, `powershell`, or `xdg-open` calls.
- **Unpacked Binary:** UPX and third-party binary packers are explicitly forbidden to prevent high-entropy detections.
- **Windows PE Resource Manifest:** Embedded with authentic Windows PE version tables and `asInvoker` execution-level manifests via `go-winres`.
- **Reproducible Path Trimming:** Built with `-trimpath` to eliminate local file paths from executable debug headers.

---

## 2. Cryptographic Specifications

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

---

## 3. Directory Layout

```
.
├── cmd/
├── internal/
│   ├── cert/
│   │   ├── cert.go          # Core cryptographic engine and file persistence
│   │   └── cert_test.go     # Comprehensive crypto unit test suite
│   └── ui/
│       └── form.go          # Interactive terminal form using Charm Huh
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

### Non-Interactive / Headless Mode
For CI/CD pipelines, container provisioning, or automated deployment scripts:
```bash
./certgen-linux-amd64 -non-interactive \
  -cn "app.internal" \
  -o "ACME Infrastructure" \
  -san-dns "app.internal,*.app.internal,localhost" \
  -san-ip "127.0.0.1,10.0.0.15" \
  -key-type "ecdsa-p256" \
  -days 365 \
  -out-dir "./certs" \
  -p12 \
  -p12-pass "changeit"
```

#### CLI Flags Reference

| Flag | Default | Description |
|---|---|---|
| `-role` | `leaf` | Certificate role: `leaf` or `ca` |
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
| `-p12` | `false` | Enable PKCS#12 bundle generation |
| `-p12-name` | `cert.p12` | PKCS#12 bundle filename |
| `-p12-pass` | `""` | Export password for PKCS#12 bundle |
| `-key-format` | `pkcs8` | Private key format: `pkcs8` or `traditional` |
| `-non-interactive`| `false` | Force headless execution without TUI |
| `-version` | `false` | Display version and architecture metadata |

---

## 6. Running Tests

Execute the full cryptographic test suite:
```bash
go test -v ./...
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

