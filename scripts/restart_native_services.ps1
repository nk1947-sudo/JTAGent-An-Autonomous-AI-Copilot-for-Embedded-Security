<#
.SYNOPSIS
Restart ONLY the native edge (8001) and orchestrator (8000) on current code. OpenOCD is never touched.

.DESCRIPTION
For a workstation where the two services run natively (not in Docker) next to a user-owned OpenOCD.
Hardware permissions are NOT inherited or widened: snapshots, the live Attack Lab probe and raw retention
are off unless you pass -ArmSnapshots / -EnableLiveJtagAttack / -RetainRawLocal explicitly.

Safety checks before anything is stopped (all read-only): OpenOCD's Tcl port must answer, the target must
not be halted (a halted core may mean an operation is mid-flight or another client owns it), and you must
confirm with -CheckpointDone that scripts/export_retained_evidence.py has been run, because runs,
plans and captures live only in the process being replaced.

The dashboard password is read as a secure string (press Enter to generate one shown only in this window).
The edge API key is generated and never printed.
#>
[CmdletBinding()]
param(
    [switch]$CheckpointDone,
    [switch]$ArmSnapshots,
    [switch]$EnableLiveJtagAttack,
    [switch]$RetainRawLocal
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if (-not $CheckpointDone) { throw "Run scripts/export_retained_evidence.py first, then pass -CheckpointDone." }

function Read-OpenOcd([string]$command) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 3000
        $client.Connect("127.0.0.1", 6666)
        $stream = $client.GetStream()
        $bytes = [Text.Encoding]::ASCII.GetBytes($command) + [byte]0x1a
        $stream.Write($bytes, 0, $bytes.Length)
        $buffer = New-Object byte[] 4096
        $count = $stream.Read($buffer, 0, $buffer.Length)
        return [Text.Encoding]::ASCII.GetString($buffer, 0, $count).TrimEnd([char]0x1a).Trim()
    } finally { $client.Dispose() }
}

$state = Read-OpenOcd "am335x.cpu curstate"
if ($state -ne "running") { throw "OpenOCD reports the target as '$state'. Refusing to restart while it is not simply running; reconcile it first." }
Write-Host "OpenOCD answered on 6666; target state: $state (read-only check)."

$targets = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match "uvicorn" -and $_.CommandLine -match "(edge|orchestrator)\.app:create_app" -and $_.CommandLine -match "--port (8000|8001)\b"
}
foreach ($p in $targets) { Write-Host "Stopping service pid $($p.ProcessId): $($p.CommandLine.Substring(0, [Math]::Min(90, $p.CommandLine.Length)))" }
$targets | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Start-Sleep -Seconds 2

$secure = Read-Host "Dashboard operator password (12+ chars; Enter to generate)" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
$generated = $false
if ($plain.Length -eq 0) {
    $plain = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(18)).TrimEnd("=").Replace("+", "-").Replace("/", "_")
    $generated = $true
}
if ($plain.Length -lt 12) { throw "Password must be at least 12 characters." }
$key = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).TrimEnd("=").Replace("+", "-").Replace("/", "_")

$env:TARGET_BACKEND = "openocd"
$env:TARGET_PROFILE = Join-Path $root "config\beaglebone-black-live.json"
$env:OPENOCD_TARGET = "am335x.cpu"
$env:OPENOCD_PORT = "6666"
$env:OPENOCD_VERSION_PREFIX = "xPack Open On-Chip Debugger 0.12.0"
$env:EDGE_API_KEY = $key
$env:DASHBOARD_PASSWORD = $plain
$env:EDGE_API_URL = "http://127.0.0.1:8001"
$env:PUBLIC_ORIGIN = "http://127.0.0.1:8000"
$env:COOKIE_SECURE = "0"
$env:ARM_SNAPSHOTS = if ($ArmSnapshots) { "1" } else { "0" }
$env:ATTACK_LAB_LIVE_JTAG = if ($EnableLiveJtagAttack) { "1" } else { "0" }
$env:RETAIN_RAW_LOCAL = if ($RetainRawLocal) { "1" } else { "0" }

New-Item -ItemType Directory -Force (Join-Path $root "logs") | Out-Null
foreach ($svc in @(@("edge", "edge.app:create_app", 8001), @("orchestrator", "orchestrator.app:create_app", 8000))) {
    $uvArgs = @("run", "--frozen", "--env-file", ".env", "python", "-m", "uvicorn", $svc[1], "--factory", "--host", "127.0.0.1", "--port", $svc[2], "--workers", "1", "--no-access-log")
    Start-Process -FilePath "uv" -ArgumentList $uvArgs -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $root "logs\$($svc[0]).out.log") -RedirectStandardError (Join-Path $root "logs\$($svc[0]).err.log")
}
foreach ($port in 8001, 8000) {
    $deadline = (Get-Date).AddSeconds(40)
    do {
        try { $health = Invoke-RestMethod "http://127.0.0.1:$port/healthz" -TimeoutSec 2 } catch { $health = $null; Start-Sleep -Milliseconds 400 }
    } until ($health -or (Get-Date) -gt $deadline)
    if (-not $health) { throw "Service on $port did not come up; see logs\." }
    Write-Host ("port {0}: {1} build {2}" -f $port, $health.status, $health.build.build_id)
}
Write-Host "Snapshots armed: $($env:ARM_SNAPSHOTS)  live Attack Lab probe: $($env:ATTACK_LAB_LIVE_JTAG)  raw retention: $($env:RETAIN_RAW_LOCAL)"
if ($generated) { Write-Host "Generated dashboard password (shown once): $plain" }
Write-Host "Open http://127.0.0.1:8000 and confirm the Readiness panel shows schema v2."

