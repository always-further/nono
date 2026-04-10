param(
    [Parameter(Mandatory = $true)]
    [string]$CertBase64,

    [Parameter(Mandatory = $true)]
    [string]$CertPassword,

    [Parameter(Mandatory = $true)]
    [string[]]$ArtifactPaths,

    # RFC 3161 timestamp server endpoint.
    # http://timestamp.digicert.com supports both the legacy Authenticode timestamp
    # protocol and RFC 3161 when addressed via /tr. Using /tr + /td sha256 here is
    # the current Microsoft-recommended practice for SHA-256 signed binaries.
    # D-12 (locked): DigiCert, SHA-256 only. D-14 (locked): signtool.exe only.
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-Signtool {
    $signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -eq $signtool) {
        throw "signtool.exe not found on PATH. The Windows SDK must be installed on the runner."
    }
    return $signtool.Source
}

function Import-SigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PfxPath,

        [Parameter(Mandatory = $true)]
        [string]$Password
    )

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    $cert = Import-PfxCertificate `
        -FilePath $PfxPath `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Password $securePassword
    return $cert.Thumbprint
}

function Remove-SigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    $certPath = "Cert:\CurrentUser\My\$Thumbprint"
    if (Test-Path -LiteralPath $certPath) {
        Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-SigntoolSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath,

        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,

        [Parameter(Mandatory = $true)]
        [string]$TimestampUrl
    )

    if (-not (Test-Path -LiteralPath $ArtifactPath)) {
        throw "Artifact not found: $ArtifactPath"
    }

    # /fd sha256   - file digest algorithm (SHA-256)
    # /sha1        - select the certificate by thumbprint
    # /tr          - RFC 3161 timestamp server URL (/td sha256 sets the timestamp digest)
    # /td sha256   - timestamp digest algorithm (SHA-256, required with /tr)
    #
    # D-12: DigiCert timestamping, SHA-256 only.
    # D-14: signtool.exe is the only signing primitive.
    & signtool.exe sign /fd sha256 /sha1 $Thumbprint /tr $TimestampUrl /td sha256 $ArtifactPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed for '$ArtifactPath' (exit $LASTEXITCODE)."
    }
}

function Invoke-SigntoolVerify {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath
    )

    # /pa  - use the default authentication policy
    # /tw  - warn if no timestamp is present (makes timestamp absence a failure mode
    #        rather than a silent success; D-12 requires timestamp-aware verification)
    & signtool.exe verify /pa /tw $ArtifactPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool verify failed for '$ArtifactPath' — signature is not valid Authenticode or is missing a timestamp (exit $LASTEXITCODE)."
    }
    Write-Host "Signature verified: $ArtifactPath"
}

# Decode certificate and write to temp PFX file
$certBytes = [System.Convert]::FromBase64String($CertBase64)
$tempFile = [System.IO.Path]::GetTempFileName()
$pfxPath = [System.IO.Path]::ChangeExtension($tempFile, ".pfx")
[System.IO.File]::Move($tempFile, $pfxPath)

try {
    [System.IO.File]::WriteAllBytes($pfxPath, $certBytes)

    Find-Signtool | Out-Null
    $thumbprint = Import-SigningCertificate -PfxPath $pfxPath -Password $CertPassword

    try {
        # Sign all artifacts
        foreach ($path in $ArtifactPaths) {
            Invoke-SigntoolSign `
                -ArtifactPath $path `
                -Thumbprint $thumbprint `
                -TimestampUrl $TimestampUrl
        }

        # Verify all artifacts. Failure here aborts; D-13 requires that CI never
        # proceeds to artifact upload if signing or verification fails.
        foreach ($path in $ArtifactPaths) {
            Invoke-SigntoolVerify -ArtifactPath $path
        }
    }
    finally {
        Remove-SigningCertificate -Thumbprint $thumbprint
    }
}
finally {
    Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
}

Write-Host "All artifacts signed and verified."
