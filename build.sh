#!/usr/bin/env bash
# Build script for Linux / macOS / POSIX Shells
# Production-Grade, Air-Gapped, EDR-Safe CertGen Builder

set -euo pipefail

echo "=========================================================="
echo "  CertGen Enterprise Offline Builder"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="${SCRIPT_DIR}/.tmp"
DIST_DIR="${SCRIPT_DIR}/dist"

mkdir -p "${TMP_DIR}"
mkdir -p "${DIST_DIR}"

export GOTMPDIR="${TMP_DIR}"

# 1. Prepare go-winres
echo ""
echo "[1/4] Preparing Windows PE Resource Tool (go-winres)..."
if command -v go-winres &> /dev/null; then
    WINRES_CMD="go-winres"
    echo "  Found go-winres in PATH"
else
    WINRES_CMD="${TMP_DIR}/winres"
    if [ ! -f "${WINRES_CMD}" ]; then
        echo "  Compiling local go-winres helper..."
        go build -o "${WINRES_CMD}" github.com/tc-hib/go-winres
    fi
    echo "  Using local go-winres helper: ${WINRES_CMD}"
fi

# 2. Compile Windows Manifest and Version Resources
echo ""
echo "[2/4] Compiling Windows PE Resources & Manifest..."
"${WINRES_CMD}" make --in "winres/winres.json"
echo "  Generated Windows PE resource objects (.syso)"

# 3. Build Windows AMD64 Executable
echo ""
echo "[3/4] Building Windows executable (CGO_ENABLED=0, -trimpath)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${DIST_DIR}/certgen-windows-amd64.exe" .
echo "  Successfully built: ${DIST_DIR}/certgen-windows-amd64.exe"

# 4. Build Linux AMD64 Executable
echo ""
echo "[4/4] Cross-compiling Linux binary (CGO_ENABLED=0, -trimpath)..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "${DIST_DIR}/certgen-linux-amd64" .
chmod +x "${DIST_DIR}/certgen-linux-amd64"
echo "  Successfully built: ${DIST_DIR}/certgen-linux-amd64"

# Summary
echo ""
echo "=========================================================="
echo "  Build Complete!"
echo "  Artifacts available in dist/:"
ls -lh "${DIST_DIR}"
echo "=========================================================="
