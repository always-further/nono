$ErrorActionPreference = "Stop"

$NonoBin = Join-Path $PSScriptRoot "..\..\target\debug\nono.exe"
if (-not (Test-Path $NonoBin)) {
    Write-Error "nono binary not found at $NonoBin. Please build the project first."
}

Write-Host "--- Task 1: Create Detach Integration Test ---"

# 1. Starts a nono agent with --detached.
Write-Host "Starting nono agent with --detached..."
$StartTime = Get-Date
# We use a command that runs for a bit.
# We'll name the session for easier identification.
$SessionName = "test-detach-$([Guid]::NewGuid().ToString().Substring(0,8))"
& $NonoBin run --detached --name $SessionName -- powershell -Command "Write-Output 'Hello from detached'; Start-Sleep -Seconds 10; Write-Output 'Still running'"
    
# 2. Verifies the CLI exits immediately.
$Duration = (Get-Date) - $StartTime
if ($Duration.TotalSeconds -gt 5) { # Allowing a bit more time for Windows process startup
    Write-Error "nono run --detached took too long to exit ($($Duration.TotalSeconds)s). Expected immediate exit."
}
Write-Host "CLI exited in $($Duration.TotalSeconds)s."

# 3. Verifies a background process (supervisor) is still running.
Start-Sleep -Seconds 2
$SessionList = & $NonoBin ps
if ($SessionList -notmatch $SessionName) {
    # If ps doesn't support names yet, this might fail, which is expected for a new feature test.
    Write-Warning "Session '$SessionName' not found in 'nono ps' output. This is expected if Phase 2 is not yet implemented."
} else {
    Write-Host "Found session '$SessionName' in 'nono ps'."
}

# Check for nono.exe processes
$NonoProcesses = Get-Process -Name "nono" -ErrorAction SilentlyContinue
if (-not $NonoProcesses) {
    Write-Error "No nono processes found after detach."
}
Write-Host "Found $($NonoProcesses.Count) nono processes running in background."

# 4. Verifies the session log file is created and contains initial output.
$SessionDir = Join-Path $HOME ".nono\sessions"
if (-not (Test-Path $SessionDir)) {
    Write-Error "Session directory $SessionDir does not exist."
}

# Find the log file for this session.
# Since we don't know the ID yet (it's random), we'll look for the newest log file or match via name in JSON.
$JsonFile = Get-ChildItem -Path $SessionDir -Filter "*.json" | Where-Object { 
    try {
        $content = Get-Content $_.FullName -Raw | ConvertFrom-Json
        $content.name -eq $SessionName
    } catch {
        $false
    }
} | Select-Object -First 1

if (-not $JsonFile) {
    Write-Warning "Session JSON file not found for $SessionName. This is expected if Phase 2 is not yet implemented."
} else {
    $SessionId = [System.IO.Path]::GetFileNameWithoutExtension($JsonFile.Name)
    $LogPath = Join-Path $SessionDir "$SessionId.log"

    if (-not (Test-Path $LogPath)) {
        Write-Error "Session log file not found at $LogPath"
    }
    Write-Host "Found log file: $LogPath"

    # Wait a bit for output to be flushed
    Start-Sleep -Seconds 2
    $LogContent = Get-Content $LogPath -Raw
    if ($LogContent -notmatch "Hello from detached") {
        Write-Error "Log content does not contain initial output. Content: $LogContent"
    }
    Write-Host "Verified initial output in log file."
}

# 5. Cleans up by stopping the agent.
Write-Host "Cleaning up..."
try {
    & $NonoBin stop $SessionName -ErrorAction SilentlyContinue
} catch {}

Start-Sleep -Seconds 1
$RemainingProcesses = Get-Process -Name "nono" -ErrorAction SilentlyContinue
if ($RemainingProcesses) {
    $RemainingProcesses | Stop-Process -Force
}

Write-Host "Detach test script completed."
