param(
    [Parameter(Mandatory = $true)]
    [string]$CertBase64,

    [Parameter(Mandatory = $true)]
    [string]$CertPassword,

    [Parameter(Mandatory = $true)]
    [string[]]$ArtifactPaths,

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
        -CertStoreLocation Cert:\LocalMachine\My `
        -Password $securePassword
    return $cert.Thumbprint
}

function Remove-SigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    $certPath = "Cert:\LocalMachine\My\$Thumbprint"
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

    & signtool.exe sign /fd sha256 /sha1 $Thumbprint /t $TimestampUrl $ArtifactPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed for '$ArtifactPath' (exit $LASTEXITCODE)."
    }
}

function Invoke-SigntoolVerify {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArtifactPath
    )

    & signtool.exe verify /pa $ArtifactPath
    if ($LASTEXITCODE -ne 0) {
        throw "signtool verify failed for '$ArtifactPath' — signature is not valid Authenticode (exit $LASTEXITCODE)."
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

        # Verify all artifacts
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
