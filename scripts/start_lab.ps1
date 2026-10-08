<#
.SYNOPSIS
    Starts the AI Usage Monitoring Lab natively on Windows (no Docker).

.DESCRIPTION
    1. Checks the native dependencies (Postgres, Elasticsearch, Kibana) are reachable.
    2. Starts Keycloak (port 8080, realm imported from config/keycloak_realm.json),
       the Mock AI backend (port 8001) and the LiteLLM gateway (port 4000),
       each in its own PowerShell window so you can watch their logs.
    3. Waits until Keycloak serves the realm and LiteLLM reports a healthy database.
    4. Runs scripts/simulate_traffic.py (skip with -SkipSimulation).

.EXAMPLE
    .\scripts\start_lab.ps1                  # start everything + run simulation
    .\scripts\start_lab.ps1 -SkipSimulation  # start services only
    .\scripts\start_lab.ps1 -Stop            # stop Keycloak + Mock AI + LiteLLM

    If scripts are blocked, run once per session:
    Set-ExecutionPolicy -Scope Process Bypass
#>
param(
    [switch]$SkipSimulation,
    [switch]$Stop,
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"

$ProjectRoot  = Split-Path -Parent $PSScriptRoot
$VenvPython   = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$LiteLLMExe   = Join-Path $ProjectRoot ".venv\Scripts\litellm.exe"
$LiteLLMRun   = Join-Path $ProjectRoot "scripts\run_litellm.py"
$LiteLLMConf  = Join-Path $ProjectRoot "config\litellm_config.yaml"
$MockAIDir    = Join-Path $ProjectRoot "config\mock_ai"
$PidFile      = Join-Path $ProjectRoot ".lab_pids"
$RealmFile    = Join-Path $ProjectRoot "config\keycloak_realm.json"

$MockAIPort   = 8001
$LiteLLMPort  = 4000
$KeycloakPort = 8080
$KeycloakRealmUrl = "http://localhost:$KeycloakPort/realms/ai-sec-realm/.well-known/openid-configuration"

# -- Helpers --------------------------------------------------------------------

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    [!]  $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [X]  $msg" -ForegroundColor Red }

function Test-Port([int]$Port) {
    $conn = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return [bool]$conn
}

function Test-Url([string]$Url, [hashtable]$Headers = @{}) {
    try {
        $null = Invoke-WebRequest -Uri $Url -Headers $Headers -UseBasicParsing -TimeoutSec 3
        return $true
    } catch {
        return $false
    }
}

function Stop-PortOwner([int]$Port) {
    $conns = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    foreach ($procId in ($conns | Select-Object -ExpandProperty OwningProcess -Unique)) {
        if ($procId -gt 0) { & cmd.exe /c "taskkill /PID $procId /T /F >nul 2>&1" }
    }
}

# -- Stop mode ------------------------------------------------------------------

if ($Stop) {
    Write-Step "Stopping lab services..."
    if (Test-Path $PidFile) {
        foreach ($procId in Get-Content $PidFile) {
            if ($procId) { & cmd.exe /c "taskkill /PID $procId /T /F >nul 2>&1" }
        }
        Remove-Item $PidFile -Force
    }
    # Catch anything still holding the ports (e.g. started manually)
    Stop-PortOwner $LiteLLMPort
    Stop-PortOwner $MockAIPort
    Stop-PortOwner $KeycloakPort
    Write-Ok "Keycloak (:$KeycloakPort), Mock AI (:$MockAIPort) and LiteLLM (:$LiteLLMPort) stopped"
    exit 0
}

# -- Banner ---------------------------------------------------------------------

Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Magenta
Write-Host "  AI USAGE MONITORING LAB - LOCAL STARTUP (Windows, no Docker)"             -ForegroundColor Magenta
Write-Host "===========================================================================" -ForegroundColor Magenta
Write-Host ""

# -- 1. Pre-flight checks -------------------------------------------------------

Write-Step "Checking virtual environment..."
if (-not (Test-Path $VenvPython) -or -not (Test-Path $LiteLLMExe)) {
    Write-Fail "Missing .venv or litellm. Expected: $VenvPython"
    Write-Host "         Create it with: py -3.12 -m venv .venv; .venv\Scripts\pip install `"litellm[proxy,extra_proxy]`" prisma fastapi uvicorn requests"
    exit 1
}
Write-Ok (& $VenvPython --version)

Write-Step "Loading settings from .env..."
$EnvFile = Join-Path $ProjectRoot ".env"
if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
            Set-Item -Path "env:$($Matches[1])" -Value $Matches[2]
        }
    }
    Write-Ok ".env loaded"
} else {
    Write-Warn "No .env found - copy .env.example to .env and set DATABASE_URL"
}
# Child windows inherit these, so LiteLLM sees them.
if (-not $env:MOCK_AI_API_BASE) { $env:MOCK_AI_API_BASE = "http://127.0.0.1:$MockAIPort/v1" }
if (-not $env:DATABASE_URL) {
    Write-Fail "DATABASE_URL is not set. Add it to .env, e.g. postgresql://postgres:<password>@127.0.0.1:5432/litellm"
    exit 1
}

Write-Step "Checking native dependencies..."
$depsOk = $true
if (Test-Port 5432) { Write-Ok "PostgreSQL       :5432" } else { Write-Fail "PostgreSQL is not listening on :5432"; $depsOk = $false }
$esUser = if ($env:ELASTIC_USERNAME) { $env:ELASTIC_USERNAME } else { "elastic" }
$esAuth = @{ Authorization = "Basic " + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${esUser}:$($env:ELASTIC_PASSWORD)")) }
if (Test-Url "http://localhost:9200" $esAuth) { Write-Ok "Elasticsearch    :9200 (authenticated as $esUser)" } else { Write-Fail "Elasticsearch is not reachable at http://localhost:9200, or ELASTIC_USERNAME/ELASTIC_PASSWORD in .env are wrong"; $depsOk = $false }
if (Test-Url "http://localhost:5601/api/status") { Write-Ok "Kibana           :5601" } else { Write-Warn "Kibana is not reachable at http://localhost:5601 (dashboards unavailable, lab still runs)" }
if (-not $depsOk) {
    Write-Fail "Start the missing services above, then re-run this script."
    exit 1
}

$startedPids = @()

# -- 2. Start Keycloak ---------------------------------------------------------

$KeycloakHome = if ($env:KEYCLOAK_HOME) { $env:KEYCLOAK_HOME } else { "C:\keycloak-24.0.1" }
$KeycloakBat  = Join-Path $KeycloakHome "bin\kc.bat"

Write-Step "Starting Keycloak on :$KeycloakPort..."
if (Test-Port $KeycloakPort) {
    Write-Warn "Port $KeycloakPort already in use - assuming Keycloak is already running"
} elseif (-not (Test-Path $KeycloakBat)) {
    Write-Warn "Keycloak not found at $KeycloakHome (set KEYCLOAK_HOME in .env) - identities will use local fallback"
} else {
    # --import-realm loads data\import\keycloak_realm.json only if the realm doesn't exist yet.
    $importDir = Join-Path $KeycloakHome "data\import"
    New-Item -ItemType Directory -Force $importDir | Out-Null
    Copy-Item $RealmFile (Join-Path $importDir "keycloak_realm.json") -Force
    $kcCmd = "`$Host.UI.RawUI.WindowTitle = 'Lab: Keycloak :$KeycloakPort'; " +
             "Set-Location '$KeycloakHome'; " +
             "& '$KeycloakBat' start-dev --http-port $KeycloakPort --import-realm"
    $p = Start-Process powershell.exe -ArgumentList "-NoExit", "-NoProfile", "-Command", $kcCmd -PassThru
    $startedPids += $p.Id
    Write-Ok "Launched in new window (PID $($p.Id))"
}

# -- 3. Start Mock AI backend --------------------------------------------------

Write-Step "Starting Mock AI backend on :$MockAIPort..."
if (Test-Port $MockAIPort) {
    Write-Warn "Port $MockAIPort already in use - assuming Mock AI is already running"
} else {
    $mockCmd = "`$Host.UI.RawUI.WindowTitle = 'Lab: Mock AI :$MockAIPort'; " +
               "Set-Location '$MockAIDir'; " +
               "& '$VenvPython' -m uvicorn app:app --host 127.0.0.1 --port $MockAIPort"
    $p = Start-Process powershell.exe -ArgumentList "-NoExit", "-NoProfile", "-Command", $mockCmd -PassThru
    $startedPids += $p.Id
    Write-Ok "Launched in new window (PID $($p.Id))"
}

# -- 4. Start LiteLLM gateway --------------------------------------------------

Write-Step "Starting LiteLLM gateway on :$LiteLLMPort..."
if (Test-Port $LiteLLMPort) {
    Write-Warn "Port $LiteLLMPort already in use - assuming LiteLLM is already running"
} else {
    # PYTHONUTF8 avoids the cp1252 UnicodeEncodeError Prisma hits on Windows.
    # run_litellm.py stops LiteLLM's os.kill(pid, 0) engine check from sending
    # Ctrl+C to the whole console (signal 0 == CTRL_C_EVENT on Windows).
    $litellmCmd = "`$Host.UI.RawUI.WindowTitle = 'Lab: LiteLLM :$LiteLLMPort'; " +
                  "`$env:PYTHONUTF8 = '1'; `$env:PYTHONIOENCODING = 'utf-8'; " +
                  "Set-Location '$ProjectRoot'; " +
                  "& '$VenvPython' '$LiteLLMRun' --config '$LiteLLMConf' --port $LiteLLMPort"
    $p = Start-Process powershell.exe -ArgumentList "-NoExit", "-NoProfile", "-Command", $litellmCmd -PassThru
    $startedPids += $p.Id
    Write-Ok "Launched in new window (PID $($p.Id))"
}

if ($startedPids.Count -gt 0) {
    Add-Content -Path $PidFile -Value $startedPids
}

# -- 5. Wait for health --------------------------------------------------------

Write-Step "Waiting for services to become healthy (timeout ${TimeoutSeconds}s)..."
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

while (-not (Test-Url "http://localhost:$MockAIPort/v1/models")) {
    if ((Get-Date) -gt $deadline) { Write-Fail "Mock AI did not start - check its window for errors"; exit 1 }
    Start-Sleep -Seconds 2
}
Write-Ok "Mock AI ready     http://localhost:$MockAIPort/v1/models"

if (Test-Path $KeycloakBat) {
    while (-not (Test-Url $KeycloakRealmUrl)) {
        if ((Get-Date) -gt $deadline) { Write-Warn "Keycloak realm not reachable - identities will use local fallback"; break }
        Start-Sleep -Seconds 3
    }
    if (Test-Url $KeycloakRealmUrl) { Write-Ok "Keycloak ready    http://localhost:$KeycloakPort (realm ai-sec-realm)" }
}

$dbStatus = $null
while ($true) {
    try {
        $r = Invoke-RestMethod -Uri "http://localhost:$LiteLLMPort/health/readiness" -TimeoutSec 5
        $dbStatus = $r.db
        if ($r.status -eq "healthy" -and $dbStatus -eq "connected") { break }
    } catch { }
    if ((Get-Date) -gt $deadline) {
        if ($dbStatus) {
            Write-Warn "LiteLLM is up but database status is '$dbStatus' - spend tracking/keys may not persist"
            break
        }
        Write-Fail "LiteLLM did not start - check its window for errors"
        exit 1
    }
    Start-Sleep -Seconds 3
}
Write-Ok "LiteLLM ready     http://localhost:$LiteLLMPort (db: $dbStatus)"

# -- 6. Run simulation ---------------------------------------------------------

if (-not $SkipSimulation) {
    Write-Host ""
    Write-Step "Running traffic & attack simulation..."
    $env:PYTHONUTF8 = "1"
    $env:PYTHONIOENCODING = "utf-8"
    Push-Location $ProjectRoot
    try {
        & $VenvPython (Join-Path $ProjectRoot "scripts\simulate_traffic.py")
        if ($LASTEXITCODE -ne 0) { Write-Fail "Simulation exited with code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

# -- Summary -------------------------------------------------------------------

Write-Host ""
Write-Host "===========================================================================" -ForegroundColor Magenta
Write-Host "  LAB RUNNING" -ForegroundColor Magenta
Write-Host "===========================================================================" -ForegroundColor Magenta
Write-Host "  Keycloak Admin   : http://localhost:$KeycloakPort  (admin / see .env)"
Write-Host "  LiteLLM Gateway  : http://localhost:$LiteLLMPort"
Write-Host "  LiteLLM Admin UI : http://localhost:$LiteLLMPort/ui  (admin / <master key>)"
Write-Host "  Mock AI Backend  : http://localhost:$MockAIPort/v1/models"
Write-Host "  Elasticsearch    : http://localhost:9200/ai-audit-logs/_search"
Write-Host "  Kibana           : http://localhost:5601"
Write-Host ""
Write-Host "  Re-run simulation: .venv\Scripts\python scripts\simulate_traffic.py"
Write-Host "  Stop services    : .\scripts\start_lab.ps1 -Stop"
Write-Host "===========================================================================" -ForegroundColor Magenta
