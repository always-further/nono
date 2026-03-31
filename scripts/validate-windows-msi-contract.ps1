param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-WixDocumentForScope {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$Binary
    )

    $repoRoot = Split-Path -Parent $PSScriptRoot
    $tempDirName = "temp-msi-contract-" + $Scope
    $tempDir = Join-Path $repoRoot $tempDirName

    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -Recurse -Force -LiteralPath $tempDir
    }

    try {
        & (Join-Path $PSScriptRoot "build-windows-msi.ps1") `
            -VersionTag "v0.0.0-preview" `
            -BinaryPath $Binary `
            -Scope $Scope `
            -OutputDir $tempDirName `
            -EmitOnly

        $wxsPath = Join-Path $tempDir ("nono-" + $Scope + ".wxs")
        if (-not (Test-Path -LiteralPath $wxsPath)) {
            throw "Expected WiX source was not generated for scope '$Scope'."
        }

        return [xml](Get-Content -LiteralPath $wxsPath -Raw)
    }
    finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -Recurse -Force -LiteralPath $tempDir
        }
    }
}

function Get-FirstNodeByLocalName {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Document,

        [Parameter(Mandatory = $true)]
        [string]$LocalName
    )

    $nodes = $Document.SelectNodes(("//*[local-name()='" + $LocalName + "']"))
    if ($null -eq $nodes -or $nodes.Count -eq 0) {
        throw "Missing <$LocalName> node in generated WiX document."
    }

    return $nodes[0]
}

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]
        $Actual,

        [Parameter(Mandatory = $true)]
        $Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

$binaryFullPath = (Resolve-Path -LiteralPath $BinaryPath).Path

$machineDoc = Get-WixDocumentForScope -Scope "machine" -Binary $binaryFullPath
$userDoc = Get-WixDocumentForScope -Scope "user" -Binary $binaryFullPath

$machinePackage = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "Package"
$userPackage = Get-FirstNodeByLocalName -Document $userDoc -LocalName "Package"
$machineMajorUpgrade = Get-FirstNodeByLocalName -Document $machineDoc -LocalName "MajorUpgrade"
$userMajorUpgrade = Get-FirstNodeByLocalName -Document $userDoc -LocalName "MajorUpgrade"

Assert-Equal -Actual $machinePackage.Scope -Expected "perMachine" -Message "Machine MSI scope mismatch"
Assert-Equal -Actual $userPackage.Scope -Expected "perUser" -Message "User MSI scope mismatch"
Assert-True -Condition ($machinePackage.UpgradeCode -ne $userPackage.UpgradeCode) -Message "Machine and user MSI must use different upgrade codes"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($machinePackage.UpgradeCode)) -Message "Machine MSI upgrade code must be present"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($userPackage.UpgradeCode)) -Message "User MSI upgrade code must be present"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($machineMajorUpgrade.DowngradeErrorMessage)) -Message "Machine MSI must declare MajorUpgrade downgrade messaging"
Assert-True -Condition (-not [string]::IsNullOrWhiteSpace($userMajorUpgrade.DowngradeErrorMessage)) -Message "User MSI must declare MajorUpgrade downgrade messaging"

$machineDirectoryXml = $machineDoc.OuterXml
$userDirectoryXml = $userDoc.OuterXml

Assert-True -Condition $machineDirectoryXml.Contains('ProgramFiles64Folder') -Message "Machine MSI must target ProgramFiles64Folder"
Assert-True -Condition $userDirectoryXml.Contains('LocalAppDataFolder') -Message "User MSI must target LocalAppDataFolder"

$machineNoRepair = $machineDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOREPAIR']")
$userNoRepair = $userDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOREPAIR']")
$machineNoModify = $machineDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOMODIFY']")
$userNoModify = $userDoc.SelectSingleNode("//*[local-name()='Property' and @Id='ARPNOMODIFY']")

if ($null -eq $machineNoRepair -or $null -eq $userNoRepair) {
    throw "Both MSI scopes must disable ARP repair in the current release contract."
}
if ($null -eq $machineNoModify -or $null -eq $userNoModify) {
    throw "Both MSI scopes must disable ARP modify in the current release contract."
}

Assert-Equal -Actual $machineNoRepair.Value -Expected "1" -Message "Machine MSI ARPNOREPAIR mismatch"
Assert-Equal -Actual $userNoRepair.Value -Expected "1" -Message "User MSI ARPNOREPAIR mismatch"
Assert-Equal -Actual $machineNoModify.Value -Expected "1" -Message "Machine MSI ARPNOMODIFY mismatch"
Assert-Equal -Actual $userNoModify.Value -Expected "1" -Message "User MSI ARPNOMODIFY mismatch"

Write-Host "Validated Windows MSI contract for machine and user scopes."
