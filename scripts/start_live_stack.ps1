[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$EnableLiveJtagAttack,
    [switch]$RetainRawLocal
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envFile = Join-Path $projectRoot ".env"
$composeFile = Join-Path $projectRoot "deploy\compose.yaml"
$localComposeFile = Join-Path $projectRoot "deploy\compose.local.yaml"

if (-not (Test-Path -LiteralPath $envFile -PathType Leaf)) {
    throw "Missing $envFile. Copy .env.example to .env and configure the local secrets first."
}
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    throw "uv is not installed or is not available on PATH."
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or is not available on PATH."
}
$openocdCommand = Get-Command openocd -ErrorAction SilentlyContinue
$openocdExe = if ($env:OPENOCD_EXE -and (Test-Path -LiteralPath $env:OPENOCD_EXE -PathType Leaf)) {
    (Resolve-Path -LiteralPath $env:OPENOCD_EXE).Path
}
elseif ($null -ne $openocdCommand) {
    $openocdCommand.Source
}
else {
    Get-ChildItem -Path "C:\OpenOCD\xpack-openocd-*\bin\openocd.exe" -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
if (-not $openocdExe) {
    throw "OpenOCD was not found. Set OPENOCD_EXE to the full path of openocd.exe."
}

function New-LocalSecret([int]$byteCount) {
    $bytes = [byte[]]::new($byteCount)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

if (-not $env:EDGE_API_KEY) {
    $env:EDGE_API_KEY = New-LocalSecret 32
}
if (-not $env:DASHBOARD_PASSWORD) {
    $env:DASHBOARD_PASSWORD = New-LocalSecret 18
}

function Test-LocalTcpPort([int]$port) {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync("127.0.0.1", $port)
        return $task.Wait(250) -and $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Dispose()
    }
}

if ((Test-LocalTcpPort 8000) -or (Test-LocalTcpPort 8001)) {
    throw "Port 8000 or 8001 is already in use. Stop the old SiliconSentinel terminals first."
}

# Live hardware remains on Windows. These values take precedence over demonstration
# settings in .env, while API, dashboard, UART and inference secrets come from .env.
$env:TARGET_BACKEND = "openocd"
$env:TARGET_PROFILE = Join-Path $projectRoot "config\beaglebone-black-live.json"
$env:OPENOCD_TARGET = "am335x.cpu"
$env:OPENOCD_PORT = "6666"
$env:OPENOCD_VERSION_PREFIX = "xPack Open On-Chip Debugger 0.12.0"
$env:ARM_SNAPSHOTS = "1"
$env:EDGE_API_URL = "http://host.docker.internal:8001"
$env:PUBLIC_ORIGIN = "http://127.0.0.1:8000"
$env:COOKIE_SECURE = "0"
$env:ATTACK_LAB_LIVE_JTAG = if ($EnableLiveJtagAttack) { "1" } else { "0" }
# Off unless asked: the edge keeps raw bytes in memory only for explicit local evidence exports.
$env:RETAIN_RAW_LOCAL = if ($RetainRawLocal) { "1" } else { "0" }

$composeArgs = @(
    "compose", "--env-file", $envFile,
    "-f", $composeFile,
    "-f", $localComposeFile,
    "up", "-d"
)
if (-not $SkipBuild) {
    $composeArgs += "--build"
}

Push-Location $projectRoot
$openocdProcess = $null
try {
    if (Test-LocalTcpPort 6666) {
        Write-Host "Using the OpenOCD service already listening on port 6666."
    }
    else {
        Write-Host "Starting OpenOCD for the C232HM and AM335x target..."
        $openocdStart = [Diagnostics.ProcessStartInfo]::new()
        $openocdStart.FileName = $openocdExe
        $openocdStart.UseShellExecute = $false
        $openocdStart.CreateNoWindow = $true
        foreach ($argument in @(
            "-f", "interface/ftdi/c232hm.cfg",
            "-c", "ftdi layout_signal nTRST -data 0x0040 -oe 0x0040; reset_config trst_only; adapter speed 100; bindto 127.0.0.1",
            "-f", "target/am335x.cfg",
            "-c", "init"
        )) {
            [void]$openocdStart.ArgumentList.Add($argument)
        }
        $openocdProcess = [Diagnostics.Process]::Start($openocdStart)
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not (Test-LocalTcpPort 6666)) {
            if ($openocdProcess.HasExited) {
                throw "OpenOCD exited before its Tcl service became ready. Check the JTAG cable and target power."
            }
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "OpenOCD did not become ready on port 6666 within 15 seconds."
            }
            Start-Sleep -Milliseconds 200
        }
    }

    Write-Host "Starting the SiliconSentinel dashboard in Docker..."
    & docker @composeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose failed to start."
    }

    Write-Host ""
    Write-Host "SiliconSentinel: http://127.0.0.1:8000"
    Write-Host "Operator password: $env:DASHBOARD_PASSWORD"
    Write-Host "The edge bridge is using local OpenOCD and UART configuration from .env."
    Write-Host "Real Attack Lab JTAG probe: $(if ($EnableLiveJtagAttack) { 'ARMED (HITL approval still required)' } else { 'disabled' })"
    Write-Host "Press Ctrl+C to stop the edge and Docker dashboard."
    Write-Host ""

    # Only this authenticated edge API must be reachable through Docker's host gateway.
    # We are already in the project root. A relative env-file argument avoids a
    # Windows PowerShell/native-argument quoting edge case that can strip the
    # backslashes from an absolute path on some installations.
    & uv run --frozen --env-file ".env" python -m uvicorn edge.app:create_app `
        --factory --host 0.0.0.0 --port 8001 --workers 1 --no-access-log
}
finally {
    Write-Host "Stopping the SiliconSentinel dashboard..."
    & docker compose --env-file $envFile -f $composeFile -f $localComposeFile down
    if ($null -ne $openocdProcess -and -not $openocdProcess.HasExited) {
        Write-Host "Stopping OpenOCD started by this launcher..."
        $openocdProcess.Kill($true)
        $openocdProcess.WaitForExit(5000)
    }
    Pop-Location
}

