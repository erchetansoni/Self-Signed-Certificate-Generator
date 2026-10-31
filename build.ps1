# Build script for Windows (PowerShell)
# Production-Grade, Air-Gapped, EDR-Safe CertGen Builder

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CertGen Enterprise Offline Builder" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Setup local temporary and distribution directories
$RootDir = $PSScriptRoot
if (-not $RootDir) { $RootDir = Get-Location }
$TmpDir = Join-Path $RootDir ".tmp"
$DistDir = Join-Path $RootDir "dist"

if (-not (Test-Path $TmpDir)) { New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null }
if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir -Force | Out-Null }

$env:GOTMPDIR = $TmpDir

# 2. Check or compile go-winres locally
Write-Host "`n[1/4] Preparing Windows PE Resource Tool (go-winres)..." -ForegroundColor Yellow
$WinResCmd = Get-Command "go-winres" -ErrorAction SilentlyContinue
$WinResExe = $null

if ($WinResCmd) {
    $WinResExe = $WinResCmd.Source
    Write-Host "  Found go-winres in PATH: $WinResExe" -ForegroundColor Green
} else {
    $LocalWinRes = Join-Path $TmpDir "winres.exe"
    if (-not (Test-Path $LocalWinRes)) {
        Write-Host "  Building go-winres helper..." -ForegroundColor DarkGray
        go build -o $LocalWinRes github.com/tc-hib/go-winres
    }
    $WinResExe = $LocalWinRes
    Write-Host "  Using local go-winres helper: $WinResExe" -ForegroundColor Green
}

# 3. Compile Windows Manifest and Version Resources
Write-Host "`n[2/4] Compiling Windows PE Resources & Manifest..." -ForegroundColor Yellow
& $WinResExe make --in "winres/winres.json"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to compile Windows resources with go-winres"
}
Write-Host "  Generated Windows PE resource object (.syso)" -ForegroundColor Green

# 4. Build Windows AMD64 Executable
Write-Host "`n[3/4] Building Windows executable (CGO_ENABLED=0, -trimpath)..." -ForegroundColor Yellow
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"
$env:GOARCH = "amd64"

$WinOutput = Join-Path $DistDir "certgen-windows-amd64.exe"
go build -trimpath -ldflags="-s -w" -o $WinOutput .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Windows compilation failed"
}
Write-Host "  Successfully built: $WinOutput" -ForegroundColor Green

# 5. Build Linux AMD64 Executable
Write-Host "`n[4/4] Cross-compiling Linux binary (CGO_ENABLED=0, -trimpath)..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"

$LinuxOutput = Join-Path $DistDir "certgen-linux-amd64"
go build -trimpath -ldflags="-s -w" -o $LinuxOutput .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Linux cross-compilation failed"
}
Write-Host "  Successfully built: $LinuxOutput" -ForegroundColor Green

# Summary
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "  Artifacts available in dist/:" -ForegroundColor Green
Get-ChildItem -Path $DistDir | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Write-Host "==========================================================" -ForegroundColor Cyan
