# Praetor - Windows health check (the doctor.sh analog for native Windows).
# Usage: .\doctor.ps1   (or: powershell -ExecutionPolicy Bypass -File doctor.ps1)
# WSL users: run ./doctor.sh inside WSL instead.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:Pass = 0; $script:Warned = 0; $script:Bad = 0

function Head($m) { Write-Host ""; Write-Host "== $m ==" -ForegroundColor Cyan }
function Pass($m) { Write-Host "  [+] $m" -ForegroundColor Green;  $script:Pass++ }
function Skip($m) { Write-Host "  [o] $m" -ForegroundColor Yellow; $script:Warned++ }
function Bad($m)  { Write-Host "  [-] $m" -ForegroundColor Red;    $script:Bad++ }

function Has($n) { $null = Get-Command $n -ErrorAction SilentlyContinue; return $? }

function Test-Port([string]$h, [int]$p) {
    try {
        $c = New-Object Net.Sockets.TcpClient
        $ok = $c.ConnectAsync($h, $p).Wait(1500)
        $c.Close(); return $ok
    } catch { return $false }
}

function Http-Status([string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -TimeoutSec 3 -UseBasicParsing
        return [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return 0
    }
}

Write-Host "Praetor doctor (Windows)" -ForegroundColor White

Head "Core toolchain"
foreach ($t in @('java','mvn','python','uv','go','git')) {
    if (Has $t) { Pass "$t present" } else { Bad "$t missing" }
}

Head "Project build"
$jar = $null
$targetDir = Join-Path $ScriptDir 'burp-extension\target'
if (Test-Path $targetDir) {
    $jar = Get-ChildItem -Path $targetDir -Filter 'praetor-burp-ext-*.jar' -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Name -notmatch '-(sources|javadoc)\.jar$' } |
           Sort-Object LastWriteTime -Descending | Select-Object -First 1
}
if ($jar) { Pass "Burp extension JAR built ($($jar.Name))" } else { Bad "Burp extension JAR not found - run setup.ps1 (mvn package)" }

$venv = Join-Path $ScriptDir 'mcp-server\.venv\Scripts\python.exe'
if (Test-Path $venv) { Pass "Python venv ready" } else { Bad "Python venv not found - run setup.ps1" }

if (Test-Path (Join-Path $ScriptDir '.mcp.json')) { Pass ".mcp.json present" } else { Skip ".mcp.json not found - run setup.ps1" }

# burp-expedition jar (non-HTTP tcp_* lane)
$expDir = Join-Path (Split-Path $ScriptDir) 'burp-expedition'
$expJar = $null
if (Test-Path (Join-Path $expDir 'build\libs')) {
    $expJar = Get-ChildItem (Join-Path $expDir 'build\libs') -Filter 'burp-expedition-*.jar' -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -notlike '*-sources.jar' } | Select-Object -First 1
}
if ($expJar) { Pass "burp-expedition JAR built ($($expJar.Name))" } else { Skip "burp-expedition JAR not built (tcp_* lane) - setup.ps1 builds it" }

Head "Burp connectivity (needs Burp running with the extension loaded)"
$code = Http-Status 'http://127.0.0.1:8111/api/health'
if ($code -eq 200) { Pass "Extension API reachable (127.0.0.1:8111)" }
else { Bad "Extension API 127.0.0.1:8111 unreachable (HTTP='$code') - is Burp running with the praetor jar loaded?" }
if (Test-Port '127.0.0.1' 8080) { Pass "Burp proxy listening on 127.0.0.1:8080" }
else { Bad "Burp proxy 127.0.0.1:8080 not listening - external recon tools will fail" }
$expPort = if ($env:EXPEDITION_API_PORT) { [int]$env:EXPEDITION_API_PORT } else { 18112 }
if ((Http-Status "http://127.0.0.1:$expPort/status") -eq 200) { Pass "burp-expedition Control API reachable (:$expPort) - tcp_* lane ready" }
else { Skip "burp-expedition Control API :$expPort unreachable - load the burp-expedition jar for the tcp_* lane" }

Head "Web recon lane"
foreach ($t in @('subfinder','httpx','nuclei','assay','katana','dalfox','ffuf','sqlmap','wafw00f','gau')) {
    if (Has $t) { Pass $t } else { Skip "$t (run setup.ps1 Phase 3)" }
}

Head "Network / mobile / secrets lane"
foreach ($t in @('nmap','nxc','gobuster','hashcat','gitleaks','trufflehog','tesseract','frida','mantis','centurion-mcp')) {
    if (Has $t) { Pass $t } else { Skip "$t (run setup.ps1 Phase 3b)" }
}
if (Test-Path (Join-Path (Join-Path $env:USERPROFILE '.local\share\seclists') 'Discovery')) { Pass "SecLists present" }
else { Skip "SecLists not found - setup.ps1 clones it, or set SECLISTS_PATH" }

Write-Host ""
Write-Host "Summary: $script:Pass ok / $script:Warned warn / $script:Bad fail" -ForegroundColor White
if ($script:Bad -gt 0) { exit 1 } else { exit 0 }
