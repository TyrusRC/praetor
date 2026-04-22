# Burp Suite Swiss Knife MCP - Windows Setup Script
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
        $jarPath = Join-Path $ScriptDir 'burp-extension\target\burpsuite-swiss-knife-0.3.0.jar'
        if (Test-Path $jarPath) { Ok "Extension built: $jarPath" } else { Fail "JAR not found at $jarPath" }
    }
} finally { Pop-Location }

Info "Setting up Python MCP server..."
Push-Location (Join-Path $ScriptDir 'mcp-server')
try {
    uv venv 2>$null | Out-Null
    uv pip install -e . | Out-Null
    Ok "MCP server installed"
    $toolCount = & uv run python -c "from burpsuite_mcp.server import mcp; print(len(mcp._tool_manager._tools))" 2>$null
    if ($toolCount -and [int]$toolCount -gt 0) { Ok "MCP server verified: $toolCount tools loaded" }
    else { Fail "MCP server failed to load" }
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
# katana needs CGO; on Windows that usually means MSYS2/MinGW - skip gracefully if it fails.
Install-PdTool 'katana'      'github.com/projectdiscovery/katana/cmd/katana'
Install-PdTool 'dalfox'      'github.com/hahwul/dalfox/v2'
Install-PdTool 'gau'         'github.com/lc/gau/v2/cmd/gau'
Install-PdTool 'waybackurls' 'github.com/tomnomnom/waybackurls'

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
    "burpsuite": {
      "command": "$VenvPythonJson",
      "args": ["-m", "burpsuite_mcp"]
    }
  }
}
"@
    Set-Content -Path $McpJson -Value $json -Encoding UTF8
    Ok "Created $McpJson"
} else {
    Ok ".mcp.json already exists - skipping"
}

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

$JarPath = Join-Path $ScriptDir 'burp-extension\target\burpsuite-swiss-knife-0.3.0.jar'
Write-Host ""
Write-Host "Project:"
if (Test-Path $JarPath)   { Write-Host "  [OK] Burp extension JAR built" -ForegroundColor Green }
else                      { Write-Host "  [-]  Burp extension JAR not found" -ForegroundColor Red }
if (Test-Path $VenvPython){ Write-Host "  [OK] Python venv ready" -ForegroundColor Green }
else                      { Write-Host "  [-]  Python venv not found" -ForegroundColor Red }
if (Test-Path $McpJson)   { Write-Host "  [OK] .mcp.json configured" -ForegroundColor Green }
else                      { Write-Host "  [-]  .mcp.json not found" -ForegroundColor Red }

Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Open Burp Suite"
Write-Host "  2. Extensions -> Add -> Java -> Select: $JarPath"
Write-Host "  3. Verify: 'Swiss Knife MCP v0.3.0 started on port 8111' in Burp output"
Write-Host "  4. Start Claude Code in this directory"
Write-Host ""
