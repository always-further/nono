#Requires -Version 5.1
# Phase 49 REQ-POC-TRUST-03: Sigstore trusted-root cache smoke script (Windows).
#
# Usage:
#   pwsh scripts/verify-trust-root-cached.ps1 <path-to-candidate-trusted_root.json>
#
# Validates that `nono setup --from-file <CANDIDATE>` succeeds and produces
# a cache file byte-identical to the input. Exits 0 on success; non-zero
# on any failure. Maintainer-only (D-49-C3) — not wired into PR CI.
#
# Pre-commit gate for .planning/templates/sigstore-rotation-refresh.md
# Step 4. See that template for the full rotation-response procedure.
#
# F-03-05 mitigation: `$ErrorActionPreference = 'Stop'` does NOT trap
# native-command failures. After every `& nono ...` invocation we explicitly
# check `$LASTEXITCODE` and `throw` on non-zero — that's the only mechanism
# that propagates a failed `nono setup` to the script's exit code.

param(
    [Parameter(Mandatory=$true)]
    [string]$Candidate
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Candidate -PathType Leaf)) {
    # Use [Console]::Error.WriteLine + explicit exit 2 to avoid Write-Error +
    # $ErrorActionPreference='Stop' terminating with the generic ExitCode 1
    # before the param-validation early-exit (exit 2) can fire.
    [Console]::Error.WriteLine("ERROR: candidate path does not exist or is not a file: $Candidate")
    exit 2
}

$tmpName = "nono-trust-root-smoke-" + [System.Guid]::NewGuid().ToString("N").Substring(0,8)
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP $tmpName) -Force

try {
    $env:NONO_TEST_HOME = $tmp.FullName
    $env:XDG_CONFIG_HOME = $tmp.FullName
    $env:NONO_NO_UPDATE_CHECK = '1'

    Write-Host "Running: nono setup --from-file $Candidate"
    & nono setup --from-file $Candidate
    if ($LASTEXITCODE -ne 0) {
        throw "nono setup --from-file failed with exit code $LASTEXITCODE"
    }

    $cache = Join-Path $tmp.FullName ".nono\trust-root\trusted_root.json"
    if (-not (Test-Path -LiteralPath $cache -PathType Leaf)) {
        throw "cache file was not created at $cache"
    }

    $candHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Candidate).Hash
    $cacheHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $cache).Hash
    if ($candHash -ne $cacheHash) {
        throw "cache file is not byte-identical to candidate; candidate=$candHash cache=$cacheHash"
    }

    Write-Host "PASS: $Candidate accepted by 'nono setup --from-file' and cache is byte-identical (SHA-256: $candHash)."
    exit 0
}
catch {
    # Use [Console]::Error.WriteLine to bypass Write-Error +
    # $ErrorActionPreference='Stop' interaction that otherwise terminates the
    # script before `exit 1` runs and surfaces as $LASTEXITCODE=0 to the caller.
    [Console]::Error.WriteLine("ERROR: $_")
    exit 1
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp.FullName)) {
        Remove-Item -Recurse -Force -LiteralPath $tmp.FullName -ErrorAction SilentlyContinue
    }
}
