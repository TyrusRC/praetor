# Praetor - Windows Setup Script
# Usage: .\setup.ps1
# If execution policy blocks the script, run via:
#   powershell -ExecutionPolicy Bypass -File setup.ps1

$ErrorActionPreference = 'Stop'

function Info($m)  { Write-Host "[*] $m" -ForegroundColor Blue }
function Ok($m)    { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m)  { Write-Host "[!] $m" -ForegroundColor Yellow }
function Fail($m)  { Write-Host "[-] $m" -ForegroundColor Red }

function Has-Command($name) {
    $null = Get-Command $name -ErrorAction SilentlyContinue
    return $?
}

# Locate the built extension jar without hardcoding a version, so a version
# bump never makes setup report "not found".
function Resolve-PraetorJar([string]$root) {
    $targetDir = Join-Path $root 'burp-extension\target'
    if (-not (Test-Path $targetDir)) { return $null }
    $hit = Get-ChildItem -Path $targetDir -Filter 'praetor-burp-ext-*.jar' -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -notmatch '-(sources|javadoc)\.jar$' } |
           Sort-Object LastWriteTime -Descending |
           Select-Object -First 1
    if ($hit) { return $hit.FullName }
    return $null
}

function Has-Winget { Has-Command 'winget' }
function Has-Choco  { Has-Command 'choco' }
function Has-Scoop  { Has-Command 'scoop' }

function Install-Via-PackageManager([string]$wingetId, [string]$chocoId, [string]$scoopId) {
    if (Has-Winget) {
        winget install --id $wingetId --accept-source-agreements --accept-package-agreements --silent
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    if (Has-Choco -and $chocoId) {
        choco install $chocoId -y
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    if (Has-Scoop -and $scoopId) {
        scoop install $scoopId
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

# --- Admin-rights notice (non-fatal) ---
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal   = New-Object Security.Principal.WindowsPrincipal $currentUser
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Warn "Not running as Administrator - winget installs may prompt UAC."
}

Info "Detected platform: windows"

# ════════════════════════════════════════════════════════════════════
# PHASE 1: Required Dependencies
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Phase 1: Required Dependencies"
Write-Host "════════════════════════════════════════════════════"

# --- Java 21+ ---
Info "Checking Java..."

function Detect-JavaBin {
    if (Has-Command 'java') { return (Get-Command java).Source }
    if ($env:JAVA_HOME -and (Test-Path "$env:JAVA_HOME\bin\java.exe")) { return "$env:JAVA_HOME\bin\java.exe" }
    return $null
}

function Parse-JavaMajor([string]$javaBin) {
    $out = & $javaBin -version 2>&1 | Out-String
    # Matches strings like version "21", version "21.0.1", version "1.8.0_342"
    if ($out -match 'version\s+"(\d+)(?:\.(\d+))?') {
        $maj = [int]$Matches[1]
        if ($maj -eq 1 -and $Matches[2]) { return [int]$Matches[2] } # e.g. 1.8 -> 8
        return $maj
    }
    return 0
}

$javaBin = Detect-JavaBin
if ($javaBin) {
    $javaMajor = Parse-JavaMajor $javaBin
    if ($javaMajor -ge 21) {
        Ok "Java $javaMajor found at $javaBin"
    } else {
        Warn "Java found at $javaBin but version=$javaMajor < 21"
        Warn "Install Java 21+: https://adoptium.net/temurin/releases/?version=21"
    }
} else {
    Warn "Java not found (checked PATH and JAVA_HOME)"
    Info "Installing Java 21..."
    $installed = Install-Via-PackageManager 'Microsoft.OpenJDK.21' 'microsoft-openjdk21' 'openjdk21'
    if (-not $installed) {
        $installed = Install-Via-PackageManager 'EclipseAdoptium.Temurin.21.JDK' 'temurin21' $null
    }
    if ($installed) {
        Ok "Java installed (restart this shell or run: refreshenv)"
    } else {
        Fail "Java installation failed - install manually: https://adoptium.net/temurin/releases/?version=21"
    }
}

# --- Maven ---
Info "Checking Maven..."
if (Has-Command 'mvn') {
    Ok "Maven found"
} else {
    Info "Installing Maven..."
    # Apache.Maven was removed from winget in 2024; scoop is the reliable path on Windows.
    if (Install-Via-PackageManager 'Apache.Maven' 'maven' 'maven') { Ok "Maven installed" }
    else { Fail "Maven installation failed - install manually: https://maven.apache.org/download.cgi" }
}

# --- Python 3.11+ ---
Info "Checking Python..."
if (Has-Command 'python') {
    $pyVer = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    $pyMinor = [int](& python -c "import sys; print(sys.version_info.minor)")
    if ($pyMinor -ge 11) { Ok "Python $pyVer found" }
    else { Warn "Python $pyVer found but < 3.11 required" }
} else {
    Warn "Python not found"
    Info "Installing Python..."
    if (Install-Via-PackageManager 'Python.Python.3.12' 'python' 'python') { Ok "Python installed" }
    else { Fail "Python installation failed - install manually: https://www.python.org/downloads/" }
}

# --- uv ---
Info "Checking uv..."
if (Has-Command 'uv') {
    Ok "uv found"
} else {
    Info "Installing uv..."
    try {
        Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
        # Add to current session path
        $env:PATH = "$env:USERPROFILE\.local\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"
        if (Has-Command 'uv') { Ok "uv installed" } else { Fail "uv install completed but not in PATH" }
    } catch {
        Fail "uv installation failed - see https://docs.astral.sh/uv/"
    }
}

# --- Go ---
Info "Checking Go..."
if (Has-Command 'go') {
    Ok "Go found"
} else {
    Info "Installing Go..."
    if (Install-Via-PackageManager 'GoLang.Go' 'golang' 'go') { Ok "Go installed" }
    else { Fail "Go installation failed - install manually: https://go.dev/dl/" }
}

# Ensure %USERPROFILE%\go\bin is on PATH for this session
$env:PATH = "$env:USERPROFILE\go\bin;$env:PATH"

# ════════════════════════════════════════════════════════════════════
# PHASE 2: Build the Project
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Phase 2: Build the Project"
Write-Host "════════════════════════════════════════════════════"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

Info "Building Burp extension..."
Push-Location (Join-Path $ScriptDir 'burp-extension')
try {
    mvn package -q
    if ($LASTEXITCODE -ne 0) { Fail "Maven build failed" }
    else {
        $jarPath = Resolve-PraetorJar $ScriptDir
        if ($jarPath) { Ok "Extension built: $jarPath" }
        else { Fail "JAR not found under burp-extension\target\" }
    }
} finally { Pop-Location }

# burp-expedition: non-HTTP TCP/UDP lane (tcp_* tools) — core, not optional.
# Second Burp extension (TyrusRC/burp-expedition): Netty TCP/UDP/SOCKS5 proxy +
# per-protocol dissectors + Control API on :18112. Cloned next to the praetor
# extension, built with its gradlew. Load the jar in Burp like the praetor one.
$ExpeditionDir = Join-Path (Split-Path $ScriptDir) 'burp-expedition'
$script:ExpJar = $null
if (Has-Command 'git') {
    if (Test-Path (Join-Path $ExpeditionDir '.git')) {
        Info "Updating burp-expedition..."
        & git -C $ExpeditionDir pull --ff-only 2>&1 | Out-Null
    } elseif (Test-Path $ExpeditionDir) {
        Warn "burp-expedition dir exists but is not a git clone - leaving as-is ($ExpeditionDir)"
    } else {
        Info "Cloning burp-expedition (TyrusRC/burp-expedition)..."
        & git clone --depth 1 https://github.com/TyrusRC/burp-expedition.git $ExpeditionDir 2>&1 | Out-Null
        if (-not (Test-Path (Join-Path $ExpeditionDir '.git'))) {
            Warn "burp-expedition clone failed - clone manually: git clone https://github.com/TyrusRC/burp-expedition.git $ExpeditionDir"
        }
    }
    if (Test-Path $ExpeditionDir) {
        Info "Building burp-expedition (gradlew shadowJar)..."
        Push-Location $ExpeditionDir
        try {
            & .\gradlew.bat shadowJar 2>&1 | Out-Null
            $script:ExpJar = Get-ChildItem (Join-Path $ExpeditionDir 'build\libs') -Filter 'burp-expedition-*.jar' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notlike '*-sources.jar' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
            if ($script:ExpJar) { Ok "burp-expedition built: $script:ExpJar" }
            else { Warn "burp-expedition build reported no jar under build\libs\" }
        } finally { Pop-Location }
    }
} else {
    Warn "git not found - skipping burp-expedition (clone+build manually: git clone ...burp-expedition.git; .\gradlew.bat shadowJar)"
}

Info "Setting up Python MCP server..."
Push-Location (Join-Path $ScriptDir 'mcp-server')
try {
    uv venv 2>$null | Out-Null
    uv pip install -e . | Out-Null
    Ok "MCP server installed"
    $toolCount = & uv run python -c "from praetor.server import mcp; print(len(mcp._tool_manager._tools))" 2>$null
    if ($toolCount -and [int]$toolCount -gt 0) { Ok "MCP server verified: $toolCount tools loaded" }
    else { Fail "MCP server failed to load" }

    # Browser tools (browser_crawl, browser_navigate, etc.) need CloakBrowser's
    # stealth Chromium. First import auto-downloads the patched binary (~200MB,
    # cached). Pre-warm now so the first MCP call doesn't pay that latency.
    Info "Warming CloakBrowser stealth Chromium (first run downloads ~200MB)..."
    & uv run python -c "import cloakbrowser" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "CloakBrowser ready" }
    else { Warn "CloakBrowser warm-up failed - browser_* tools will trigger the download on first call instead" }
} finally { Pop-Location }

# ════════════════════════════════════════════════════════════════════
# PHASE 3: Optional - Recon Tools
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Phase 3: Recon Tools (optional)"
Write-Host "════════════════════════════════════════════════════"
Info "These tools enhance reconnaissance. They are NOT required."
Write-Host ""

function Install-PdTool([string]$name, [string]$goPackage) {
    if (Has-Command $name) { Ok "$name already installed"; return }
    Info "Installing $name..."
    go install -v "$goPackage@latest"
    if (Has-Command $name) { Ok "$name installed" }
    else { Warn "$name install completed but binary not in PATH (check $env:USERPROFILE\go\bin)" }
}

Install-PdTool 'subfinder'   'github.com/projectdiscovery/subfinder/v2/cmd/subfinder'
Install-PdTool 'httpx'       'github.com/projectdiscovery/httpx/cmd/httpx'
Install-PdTool 'nuclei'      'github.com/projectdiscovery/nuclei/v3/cmd/nuclei'
Install-PdTool 'assay'       'github.com/TyrusRC/assay/cmd/assay'   # default web-scan engine (run_assay)
# katana needs CGO; on Windows that usually means MSYS2/MinGW - skip gracefully if it fails.
Install-PdTool 'katana'      'github.com/projectdiscovery/katana/cmd/katana'
Install-PdTool 'dalfox'      'github.com/hahwul/dalfox/v2'
Install-PdTool 'gau'         'github.com/lc/gau/v2/cmd/gau'
Install-PdTool 'waybackurls' 'github.com/tomnomnom/waybackurls'
Install-PdTool 'ffuf'        'github.com/ffuf/ffuf/v2'
Install-PdTool 'amass'       'github.com/owasp-amass/amass/v4/cmd/amass'

# Python CLI tools — installed via `uv tool install` (isolated venv per
# tool, same UX as pipx). Project standardizes on uv; never pip.
function Install-UvTool([string]$name) {
    if (Has-Command $name) { Ok "$name already installed"; return }
    Info "Installing $name..."
    & uv tool install $name 2>&1 | Out-Null
    if (Has-Command $name) { Ok "$name installed" }
    else { Warn "$name install failed - retry: uv tool install $name" }
}

Install-UvTool 'sqlmap'
Install-UvTool 'commix'
Install-UvTool 'wafw00f'
Install-UvTool 'arjun'

# Praetor engines, installed from git: mantis (run_mantis source-audit; needs
# opengrep on PATH) and centurion (mobile engine, loaded as a companion MCP
# server alongside praetor — see examples/mcp-clients/claude-code.mcp.json).
function Install-GitTool([string]$name, [string]$url) {
    if (Has-Command $name) { Ok "$name already installed"; return }
    Info "Installing $name (git)..."
    & uv tool install $url 2>&1 | Out-Null
    if (Has-Command $name) { Ok "$name installed" }
    else { Warn "$name install failed - retry: uv tool install $url" }
}
Install-GitTool 'mantis'        'git+https://github.com/TyrusRC/mantis.git'
Install-GitTool 'centurion-mcp' 'git+https://github.com/TyrusRC/centurion.git'

# Custom nuclei templates (TyrusRC/custom-nuclei-templates) — cloned into the
# user data dir run_assay auto-detects (~/.local/share/praetor/... expands to
# $USERPROFILE\.local\share\praetor\custom-nuclei-templates on Windows).
$CustomTplDir = Join-Path $env:USERPROFILE '.local\share\praetor\custom-nuclei-templates'
if (Has-Command 'git') {
    if (Test-Path (Join-Path $CustomTplDir '.git')) {
        Info "Updating custom nuclei templates..."
        & git -C $CustomTplDir pull --ff-only 2>&1 | Out-Null
        Ok "custom nuclei templates updated ($CustomTplDir)"
    } elseif (Test-Path $CustomTplDir) {
        Warn "custom templates dir exists but is not a git clone - leaving as-is ($CustomTplDir)"
    } else {
        Info "Cloning custom nuclei templates (TyrusRC/custom-nuclei-templates)..."
        New-Item -ItemType Directory -Force -Path (Split-Path $CustomTplDir) | Out-Null
        & git clone --depth 1 https://github.com/TyrusRC/custom-nuclei-templates.git $CustomTplDir 2>&1 | Out-Null
        if (Test-Path (Join-Path $CustomTplDir '.git')) { Ok "custom nuclei templates cloned ($CustomTplDir)" }
        else { Warn "custom templates clone failed - clone manually into $CustomTplDir" }
    }
} else {
    Warn "git not found - skipping custom nuclei templates (run_assay auto-detects $CustomTplDir when present)"
}

# ════════════════════════════════════════════════════════════════════
# PHASE 3b: Network / mobile-dynamic / OCR + secrets (core lanes)
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Phase 3b: Network / mobile / OCR + secrets"
Write-Host "════════════════════════════════════════════════════"
Info "These back the network, mobile-dynamic, OCR, and secrets lanes."
Write-Host ""

# System tools via winget/choco/scoop. responder, john-jumbo, and
# libimobiledevice/iproxy are Linux-oriented — use WSL for those lanes.
function Install-Sys([string]$bin, [string]$winget, [string]$choco, [string]$scoop) {
    if (Has-Command $bin) { Ok "$bin already installed"; return }
    Info "Installing $bin..."
    if (Install-Via-PackageManager $winget $choco $scoop) { Ok "$bin installed" }
    else { Warn "$bin install failed - install manually ($winget / $choco / $scoop)" }
}
Install-Sys 'nmap'      'Insecure.Nmap'            'nmap'      'nmap'
Install-Sys 'hashcat'   'hashcat.hashcat'          'hashcat'   'hashcat'
Install-Sys 'tesseract' 'UB-Mannheim.TesseractOCR' 'tesseract' 'tesseract'   # OCR / screenshot redaction

# Go tools (gobuster, gitleaks, trufflehog) — reuse the PD go-install helper.
Install-PdTool 'gobuster'   'github.com/OJ/gobuster/v3'
Install-PdTool 'gitleaks'   'github.com/zricethezav/gitleaks/v8'
Install-PdTool 'trufflehog' 'github.com/trufflesecurity/trufflehog/v3'

# Python network + mobile-dynamic tools (uv tool install, isolated venvs).
Install-UvTool 'impacket'          # impacket-* scripts
Install-UvTool 'netexec'           # nxc
Install-UvTool 'bloodhound-python' # AD graph collector
Install-UvTool 'certipy-ad'        # AD CS
# frida-tools ships the `frida` CLI (mobile dynamic lane: mobile_frida_run/_snippet).
if (Has-Command 'frida') { Ok "frida already installed" }
else {
    Info "Installing frida-tools..."
    & uv tool install frida-tools 2>&1 | Out-Null
    if (Has-Command 'frida') { Ok "frida installed" }
    else { Warn "frida install failed - retry: uv tool install frida-tools" }
}

# SecLists -> %USERPROFILE%\.local\share\seclists. detect_seclists() auto-finds
# this path on every OS (no SECLISTS_PATH needed); set SECLISTS_PATH to override.
$SecListsDir = Join-Path $env:USERPROFILE '.local\share\seclists'
if (Has-Command 'git') {
    if (Test-Path (Join-Path $SecListsDir 'Discovery')) {
        Ok "SecLists present ($SecListsDir)"
    } else {
        Info "Cloning SecLists (shallow, ~1GB) to $SecListsDir ..."
        New-Item -ItemType Directory -Force -Path (Split-Path $SecListsDir) | Out-Null
        & git clone --depth 1 https://github.com/danielmiessler/SecLists.git $SecListsDir 2>&1 | Out-Null
        if (Test-Path (Join-Path $SecListsDir 'Discovery')) { Ok "SecLists cloned ($SecListsDir)" }
        else { Warn "SecLists clone failed - clone manually into $SecListsDir, or set SECLISTS_PATH" }
    }
} else {
    Warn "git not found - skipping SecLists (set SECLISTS_PATH to an existing clone)"
}

# ════════════════════════════════════════════════════════════════════
# PHASE 4: Generate .mcp.json
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Phase 4: Claude Code Configuration"
Write-Host "════════════════════════════════════════════════════"

$McpJson    = Join-Path $ScriptDir '.mcp.json'
$VenvPython = Join-Path $ScriptDir 'mcp-server\.venv\Scripts\python.exe'

if (-not (Test-Path $McpJson)) {
    Info "Generating .mcp.json..."
    $VenvPythonJson = $VenvPython -replace '\\','/'
    $json = @"
{
  "mcpServers": {
    "praetor": {
      "command": "$VenvPythonJson",
      "args": ["-m", "praetor"]
    }
  }
}
"@
    Set-Content -Path $McpJson -Value $json -Encoding UTF8
    Ok "Created $McpJson"
} else {
    Ok ".mcp.json already exists - keeping"
}

# Ensure Claude Code is allowed to start the praetor server (drop from
# disabledMcpjsonServers, add to enabledMcpjsonServers).
$SettingsLocal = Join-Path $ScriptDir '.claude\settings.local.json'
New-Item -ItemType Directory -Force -Path (Split-Path $SettingsLocal) | Out-Null
$pyEnable = @'
import json, os, sys
p = sys.argv[1]
try:
    d = json.load(open(p)) if os.path.exists(p) else {}
except Exception:
    d = {}
d["disabledMcpjsonServers"] = [s for s in d.get("disabledMcpjsonServers", []) if s != "praetor"]
if "praetor" not in d.get("enabledMcpjsonServers", []):
    d["enabledMcpjsonServers"] = d.get("enabledMcpjsonServers", []) + ["praetor"]
json.dump(d, open(p, "w"), indent=2)
'@
$pyEnable | & $VenvPython - $SettingsLocal
Ok "praetor MCP server enabled in .claude\settings.local.json"

# ════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "════════════════════════════════════════════════════"
Write-Host "  Setup Complete"
Write-Host "════════════════════════════════════════════════════"
Write-Host ""

function Check($name) {
    if (Has-Command $name) { Write-Host "  [OK] $name" -ForegroundColor Green }
    else                   { Write-Host "  [-]  $name (not found)" -ForegroundColor Red }
}

Write-Host "Required:"
Check 'java'; Check 'mvn'; Check 'python'; Check 'uv'; Check 'go'
Write-Host ""
Write-Host "Optional (recon):"
Check 'subfinder'; Check 'httpx'; Check 'nuclei'; Check 'katana'; Check 'dalfox'; Check 'gau'; Check 'waybackurls'
Check 'ffuf'; Check 'sqlmap'

$JarPath = Resolve-PraetorJar $ScriptDir
Write-Host ""
Write-Host "Project:"
if ($JarPath)             { Write-Host "  [OK] Burp extension JAR built: $JarPath" -ForegroundColor Green }
else                      { Write-Host "  [-]  Burp extension JAR not found" -ForegroundColor Red }
if (Test-Path $VenvPython){ Write-Host "  [OK] Python venv ready" -ForegroundColor Green }
else                      { Write-Host "  [-]  Python venv not found" -ForegroundColor Red }
if (Test-Path $McpJson)   { Write-Host "  [OK] .mcp.json configured" -ForegroundColor Green }
else                      { Write-Host "  [-]  .mcp.json not found" -ForegroundColor Red }

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Open Burp Suite"
Write-Host "  2. Extensions -> Add -> Java -> Select: $JarPath"
if ($script:ExpJar) {
    Write-Host "     Add the second extension the same way -> Select: $script:ExpJar"
    Write-Host "     (burp-expedition - the tcp_* non-HTTP lane, Control API on :18112)"
}
Write-Host "  3. Verify: 'Praetor MCP started on port 8111' in Burp output"
Write-Host "  4. Start Claude Code in this directory"
Write-Host ""
