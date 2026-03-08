#Requires -Version 5.1
<#
.SYNOPSIS
    Crust Installer for Windows.
    https://getcrust.io

.DESCRIPTION
    Installs the Crust binary to %LOCALAPPDATA%\Crust\.
    Automatically installs Go and Git if missing.

.PARAMETER Version
    Install a specific version or branch (e.g. v2.0.0, main). Default: latest.

.PARAMETER NoTUI
    Build without TUI dependencies (plain text only). Also skips font install.

.PARAMETER NoFont
    Skip Nerd Font installation.

.PARAMETER Uninstall
    Uninstall crust (keeps rules, config, secrets, DB).

.PARAMETER Purge
    Uninstall crust and delete DB (keeps config, secrets, rules).

.PARAMETER Help
    Show usage help.

.EXAMPLE
    irm https://raw.githubusercontent.com/BakeLens/crust/main/install.ps1 | iex

.EXAMPLE
    .\install.ps1 -Version v2.0.0
    .\install.ps1 -NoTUI
#>
param(
    [string]$Version = "latest",
    [switch]$NoTUI,
    [switch]$NoFont,
    [switch]$Uninstall,
    [switch]$Purge,
    [switch]$SourceOnly,
    [Alias("h")]
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# ─── Configuration ────────────────────────────────────────────────────────────
$GitHubRepo  = "BakeLens/crust"
$BinaryName  = "crust.exe"
$InstallDir  = Join-Path $env:LOCALAPPDATA "Crust"
$DataDir     = Join-Path $env:USERPROFILE  ".crust"
$GoMinVer    = "1.26.1"

# ─── Plain mode (matches Go TUI IsPlainMode logic) ───────────────────────────
$PlainMode = $env:NO_COLOR -ne $null -or $env:CI -eq "true" -or -not [Environment]::UserInteractive

# ─── TUI helpers ─────────────────────────────────────────────────────────────
$script:StepN     = 0
$script:StepTotal = 0

function Initialize-Steps([int]$total) {
    $script:StepN     = 0
    $script:StepTotal = $total
}

function Write-Step([string]$label) {
    $script:StepN++
    $barWidth = 20
    $filled   = [int]([Math]::Floor($script:StepN * $barWidth / $script:StepTotal))
    $empty    = $barWidth - $filled
    $bar      = ("█" * $filled) + ("░" * $empty)
    $pct      = [int]([Math]::Floor($script:StepN * 100 / $script:StepTotal))
    Write-Host ""
    if ($PlainMode) {
        Write-Host "[$($script:StepN)/$($script:StepTotal)] $label"
    } else {
        Write-Host "◆ " -NoNewline -ForegroundColor Blue
        Write-Host "[$($script:StepN)/$($script:StepTotal)] $label  " -NoNewline -ForegroundColor White
        Write-Host "$bar $pct%" -ForegroundColor DarkGray
    }
}

function Write-Ok([string]$msg) {
    if ($PlainMode) { Write-Host "    OK  $msg" }
    else { Write-Host "    ✔  $msg" -ForegroundColor Green }
}

function Write-Fail([string]$msg) {
    if ($PlainMode) { Write-Host "    ERR $msg" -ForegroundColor Red }
    else { Write-Host "    ✖  $msg" -ForegroundColor Red }
    exit 1
}

function Write-Warn([string]$msg) {
    if ($PlainMode) { Write-Host "    WRN $msg" -ForegroundColor Yellow }
    else { Write-Host "    ⚠  $msg" -ForegroundColor Yellow }
}

function Write-Info([string]$msg) {
    if ($PlainMode) { Write-Host "    ... $msg" }
    else { Write-Host "    ℹ  $msg" -ForegroundColor Cyan }
}

function Write-Running([string]$msg) {
    if ($PlainMode) { Write-Host "    ... $msg..." }
    else { Write-Host "    ●  $msg..." -ForegroundColor Blue }
}

# ─── Banner ───────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    if ($PlainMode) {
        Write-Host "CRUST - Secure Gateway for AI Agents"
    } else {
        Write-Host "▄███▄  ████▄  █   █  ▄███▄  █████" -ForegroundColor Yellow
        Write-Host "█      █   █  █   █  █        █   " -ForegroundColor Yellow
        Write-Host "█      ████▀  █   █  ▀███▄    █   " -ForegroundColor Yellow
        Write-Host "█      █  █   █   █      █    █   " -ForegroundColor Yellow
        Write-Host "▀███▀  █   █  ▀███▀  ▀███▀    █   " -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Secure Gateway for AI Agents" -ForegroundColor Blue
    }
    Write-Host ""
}

# ─── Utilities ────────────────────────────────────────────────────────────────
function Test-Command([string]$Name) {
    $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-LatestVersion {
    $url = "https://api.github.com/repos/$GitHubRepo/releases/latest"
    try {
        $release = Invoke-RestMethod -Uri $url -UseBasicParsing
        return $release.tag_name
    } catch {
        return "main"
    }
}

# ─── Go version helpers ───────────────────────────────────────────────────────
function Get-GoVersion {
    try {
        $raw = (& go version 2>$null) -replace '.*go(\d+\.\d+(?:\.\d+)?).*', '$1'
        return $raw.Trim()
    } catch { return $null }
}

function Test-GoVersionOk {
    $v = Get-GoVersion
    if (-not $v) { return $false }
    $vp = $v       -split '\.'
    $rp = $GoMinVer -split '\.'
    for ($i = 0; $i -lt $rp.Count; $i++) {
        $vn = if ($i -lt $vp.Count) { [int]$vp[$i] } else { 0 }
        $rn = [int]$rp[$i]
        if ($vn -gt $rn) { return $true }
        if ($vn -lt $rn) { return $false }
    }
    return $true  # equal to minimum
}

# Refresh the current process PATH from the Windows registry (Machine + User).
function Update-ProcessPath {
    $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                [Environment]::GetEnvironmentVariable("PATH", "User")
}

# ─── Dependency auto-install ──────────────────────────────────────────────────
function Install-GoLang {
    if (Test-GoVersionOk) {
        Write-Ok "Go $(Get-GoVersion)"
        return
    }

    if (Test-Command "go") {
        Write-Warn "Go $(Get-GoVersion) found — ${GoMinVer}+ required, upgrading"
    } else {
        Write-Info "Go not found — installing ${GoMinVer}"
    }

    # Try winget first (available on Windows 10 1709+ / Windows 11)
    if (Test-Command "winget") {
        Write-Running "Installing Go via winget"
        try {
            $null = & winget install --id GoLang.Go --silent `
                --accept-package-agreements --accept-source-agreements 2>&1
            # Refresh PATH from registry
            Update-ProcessPath
            if (Test-GoVersionOk) {
                Write-Ok "Go $(Get-GoVersion) installed via winget"
                return
            }
        } catch {}
        Write-Warn "winget install failed — trying direct download"
    }

    # Direct download of Go MSI from go.dev
    $cpuArch = (Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue).Architecture
    $arch = if ($cpuArch -eq 12) { "arm64" } else { "amd64" }
    $msiUrl = "https://dl.google.com/go/go${GoMinVer}.windows-${arch}.msi"
    $tmpMsi = Join-Path ([IO.Path]::GetTempPath()) "crust-go-$(Get-Random).msi"

    Write-Running "Downloading Go ${GoMinVer}"
    try {
        Invoke-WebRequest -Uri $msiUrl -OutFile $tmpMsi -UseBasicParsing
    } catch {
        Write-Fail "Go download failed. Install from https://go.dev/dl/ and re-run."
    }

    Write-Running "Installing Go ${GoMinVer} (this may take a moment)"
    $proc = Start-Process msiexec.exe `
        -ArgumentList "/i `"$tmpMsi`" /quiet /norestart" -Wait -PassThru
    Remove-Item $tmpMsi -Force -ErrorAction SilentlyContinue

    if ($proc.ExitCode -ne 0) {
        Write-Fail "Go MSI install failed (exit $($proc.ExitCode)). Install from https://go.dev/dl/"
    }

    # Refresh PATH after MSI install
    Update-ProcessPath

    if (Test-GoVersionOk) {
        Write-Ok "Go $(Get-GoVersion) installed"
    } else {
        Write-Warn "Go installed — restart PowerShell and re-run if 'go' is not found"
    }
}

function Install-GitTool {
    if (Test-Command "git") {
        $v = (& git --version 2>$null) -replace 'git version ', ''
        Write-Ok "git $v"
        return
    }

    Write-Info "git not found — installing"

    if (Test-Command "winget") {
        Write-Running "Installing git via winget"
        try {
            $null = & winget install --id Git.Git --silent `
                --accept-package-agreements --accept-source-agreements 2>&1
            Update-ProcessPath
            if (Test-Command "git") {
                Write-Ok "git installed via winget"
                return
            }
        } catch {}
        Write-Warn "winget install failed"
    }

    Write-Fail "git not found. Install from https://git-scm.com/ and re-run."
}

function Install-NerdFont {
    if ($NoTUI -or $NoFont) { return }

    $fontDir = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Fonts"
    if (Test-Path (Join-Path $fontDir "CascadiaMonoNF*.ttf")) {
        Write-Ok "Cascadia Mono NF already installed"
        return
    }

    $fontUrl = "https://github.com/ryanoasis/nerd-fonts/releases/download/v3.3.0/CascadiaMono.zip"
    $tmpZip  = Join-Path ([IO.Path]::GetTempPath()) "crust-font-$(Get-Random).zip"

    Write-Running "Downloading Cascadia Mono NF"
    try {
        Invoke-WebRequest -Uri $fontUrl -OutFile $tmpZip -UseBasicParsing
    } catch {
        Write-Warn "Font download failed (non-fatal)"
        return
    }

    try {
        New-Item -ItemType Directory -Path $fontDir -Force | Out-Null
        $tmpExtract = Join-Path ([IO.Path]::GetTempPath()) "crust-font-extract-$(Get-Random)"
        Expand-Archive -Path $tmpZip -DestinationPath $tmpExtract -Force
        $ttfFiles = Get-ChildItem -Path $tmpExtract -Filter "*.ttf" -Recurse
        foreach ($ttf in $ttfFiles) {
            Copy-Item $ttf.FullName (Join-Path $fontDir $ttf.Name) -Force
        }
        # Register fonts per-user (no admin needed)
        $regPath = "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts"
        foreach ($ttf in $ttfFiles) {
            Set-ItemProperty -Path $regPath -Name $ttf.BaseName `
                -Value (Join-Path $fontDir $ttf.Name) -ErrorAction SilentlyContinue
        }
        Write-Ok "Font installed to $fontDir"
        Remove-Item $tmpExtract -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Font extraction failed (non-fatal)"
    } finally {
        Remove-Item $tmpZip -Force -ErrorAction SilentlyContinue
    }
}

# ─── Source-only mode ─────────────────────────────────────────────────────
# When dot-sourced with -SourceOnly, export functions without running main.
# Usage: . .\install.ps1 -SourceOnly
if ($SourceOnly) { return }

# ─── Uninstall ────────────────────────────────────────────────────────────────
if ($Help) {
    Write-Host "Crust Installer"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version <ver>   Install specific version or branch (e.g. v2.0.0, main)"
    Write-Host "  -NoTUI           Build without TUI dependencies (plain text only)"
    Write-Host "  -NoFont          Skip Nerd Font installation"
    Write-Host "  -Uninstall       Uninstall crust (keeps rules, config, secrets, DB)"
    Write-Host "  -Purge           Uninstall crust and delete DB (keeps config, secrets, rules)"
    Write-Host "  -Help, -h        Show this help"
    exit 0
}

if ($Purge) { $Uninstall = $true }

if ($Uninstall) {
    Write-Banner
    Write-Host "Uninstalling Crust..." -ForegroundColor White
    Write-Host ""

    if (Test-Command "crust") {
        Write-Running "Stopping crust"
        try { crust stop 2>$null } catch {}
        Write-Ok "crust stopped"
    }

    $crustBin = Join-Path $InstallDir $BinaryName
    if (Test-Path $crustBin) {
        Write-Running "Removing shell completion"
        try { & $crustBin completion --uninstall 2>$null } catch {}
        Write-Ok "Shell completion removed"

        Write-Running "Removing binary"
        Remove-Item $crustBin -Force
        Write-Ok "Binary removed: $crustBin"
    }

    if ((Test-Path $InstallDir) -and @(Get-ChildItem $InstallDir).Count -eq 0) {
        Remove-Item $InstallDir -Force
    }

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -like "*$InstallDir*") {
        $newPath = ($userPath -split ';' | Where-Object { $_ -ne $InstallDir }) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Ok "PATH updated"
    }

    if (Test-Path $DataDir) {
        Write-Host ""

        # ── Runtime files (always removed silently) ───────────────────────────
        @("crust.pid", "crust.port", "crust.log") | ForEach-Object {
            $f = Join-Path $DataDir $_
            if (Test-Path $f) { Remove-Item $f -Force -ErrorAction SilentlyContinue }
        }
        Get-ChildItem $DataDir -Filter "crust-api-*.sock" -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue

        # ── Telemetry database (purge=delete, interactive=prompt, else keep) ────
        $dbPath = Join-Path $DataDir "crust.db"
        if (Test-Path $dbPath) {
            $confirm = if ($Purge) { 'y' }
                       elseif (-not $PlainMode) { Read-Host "  Remove telemetry database ($dbPath)? [y/N]" }
                       else { 'n' }
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Remove-Item $dbPath -Force -ErrorAction SilentlyContinue
                Write-Ok "Telemetry database removed"
            } else {
                Write-Info "Database kept: $dbPath"
            }
        }

        # ── User data (always kept) ───────────────────────────────────────────
        # rules.d  — user-authored security rules
        # config.yaml — user configuration
        # secrets.json — stored API keys
        $configPath  = Join-Path $DataDir "config.yaml"
        $secretsPath = Join-Path $DataDir "secrets.json"
        $rulesDir    = Join-Path $DataDir "rules.d"
        if (Test-Path $configPath)  { Write-Info "Config kept:  $configPath" }
        if (Test-Path $secretsPath) { Write-Info "Secrets kept: $secretsPath" }
        if ((Test-Path $rulesDir) -and @(Get-ChildItem $rulesDir -ErrorAction SilentlyContinue).Count -gt 0) {
            Write-Info "Rules kept:   $rulesDir"
        }

        # Remove the data dir itself only if nothing remains.
        if (@(Get-ChildItem $DataDir -ErrorAction SilentlyContinue).Count -eq 0) {
            Remove-Item $DataDir -Force -ErrorAction SilentlyContinue
            Write-Ok "Data directory removed"
        }
    }

    Write-Host ""
    Write-Host "Crust uninstalled successfully." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ─── Main ─────────────────────────────────────────────────────────────────────
Write-Banner
Initialize-Steps 7

Write-Step "Detecting system"
$Arch = try {
    $a = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($a) { "X64" { "amd64" } "Arm64" { "arm64" } default { throw "Unsupported: $a" } }
} catch { Write-Fail $_.Exception.Message }
Write-Ok "OS: windows  ·  Arch: $Arch"

Write-Step "Checking requirements"
Install-GitTool
Install-GoLang

Write-Step "Fetching version"
if ($Version -eq "latest") {
    Write-Running "Fetching latest version"
    $Version = Get-LatestVersion
    Write-Ok "Version $Version"
} else {
    Write-Ok "Version $Version"
}

$TmpDir = Join-Path ([IO.Path]::GetTempPath()) "crust-install-$(Get-Random)"
try {
    Write-Step "Cloning repository"
    $CloneUrl  = "https://github.com/$GitHubRepo.git"
    & git clone --depth 1 --branch $Version $CloneUrl $TmpDir 2>$null
    if ($LASTEXITCODE -ne 0) {
        & git clone --depth 1 $CloneUrl $TmpDir
        if ($LASTEXITCODE -ne 0) { Write-Fail "Clone failed — check your internet connection" }
    }
    Write-Ok "Repository cloned"

    Write-Step "Building Crust"
    $versionFlag = $Version -replace '^v', ''
    $buildArgs = @("build", "-ldflags", "-X main.Version=$versionFlag", "-o", "crust.exe", ".")
    if ($NoTUI) { $buildArgs = @("build", "-tags", "notui") + $buildArgs[1..($buildArgs.Count-1)] }
    Push-Location $TmpDir
    try {
        $null = & go fix ./... 2>&1
        Write-Running "Building Crust"
        & go @buildArgs
        if ($LASTEXITCODE -ne 0) { Write-Fail "Build failed" }
        Write-Ok "Build complete"
    } finally { Pop-Location }

    Write-Step "Installing"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $TmpDir "crust.exe") (Join-Path $InstallDir $BinaryName) -Force
    Write-Ok "Installed to $InstallDir\$BinaryName"

    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $DataDir "rules.d") -Force | Out-Null
    Write-Ok "Data directory: $DataDir"

    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$InstallDir;$userPath", "User")
        $env:PATH = "$InstallDir;$env:PATH"
        Write-Ok "Added $InstallDir to PATH (restart terminal to apply)"
    }

    Write-Step "Finalizing"
    $crustBin = Join-Path $InstallDir $BinaryName
    try {
        & $crustBin completion --install 2>$null | Out-Null
        Write-Ok "Shell completion installed — restart your shell to activate"
    } catch {
        Write-Warn "Shell completion skipped (non-fatal)"
    }

    Install-NerdFont

    Write-Host ""
    if ($PlainMode) { Write-Host "Crust installed successfully!" }
    else { Write-Host "  ◆ Crust installed successfully!" -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Binary  $InstallDir\$BinaryName" -ForegroundColor Cyan
    Write-Host "  Data    $DataDir\" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Quick Start"
    Write-Host ""
    Write-Host "    crust start      # Start with interactive setup"
    Write-Host "    crust status     # Check status"
    Write-Host "    crust logs -f    # Follow logs"
    Write-Host "    crust stop       # Stop crust"
    Write-Host ""
} finally {
    if (Test-Path $TmpDir) {
        Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
