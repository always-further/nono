param(
    [Parameter(Mandatory = $true)]
    [string]$VersionTag,

    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,

    [ValidateSet("machine", "user")]
    [string]$Scope = "machine",

    [string]$OutputDir = "dist/windows",

    [string]$Manufacturer = "Luke Hinds",

    [switch]$EmitOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-MsiVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Tag
    )

    $normalized = $Tag.Trim()
    if ($normalized.StartsWith("v")) {
        $normalized = $normalized.Substring(1)
    }

    $coreVersion = ($normalized -split "-", 2)[0]
    $parts = $coreVersion -split "\."
    if ($parts.Count -lt 3) {
        throw "MSI packaging requires a semantic version with at least major.minor.patch; got '$Tag'."
    }

    $numericParts = @()
    foreach ($part in $parts[0..([Math]::Min($parts.Count, 4) - 1)]) {
        $parsed = 0
        if (-not [int]::TryParse($part, [ref]$parsed)) {
            throw "MSI version components must be numeric; got '$part' in '$Tag'."
        }
        $numericParts += [string]$parsed
    }

    while ($numericParts.Count -lt 3) {
        $numericParts += "0"
    }

    return ($numericParts -join ".")
}

function Get-ScopeMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InstallScope
    )

    switch ($InstallScope) {
        "machine" {
            return @{
                PackageScope = "perMachine"
                DirectoryXml = @"
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="nono" />
    </StandardDirectory>
"@
                RegistryRoot = "HKLM"
                SystemPath = "yes"
                UpgradeCode = "D5948D55-89A4-4F09-AB43-44DBA9D25D1A"
                PackageSuffix = "machine"
                ScopeLabel = "administrative install"
            }
        }
        "user" {
            return @{
                PackageScope = "perUser"
                DirectoryXml = @"
    <StandardDirectory Id="LocalAppDataFolder">
      <Directory Id="USERPROGRAMS" Name="Programs">
        <Directory Id="INSTALLFOLDER" Name="nono" />
      </Directory>
    </StandardDirectory>
"@
                RegistryRoot = "HKCU"
                SystemPath = "no"
                UpgradeCode = "5451E72C-E0C4-4BF8-B9EA-0D6A22AA80E4"
                PackageSuffix = "user"
                ScopeLabel = "end-user install"
            }
        }
        default {
            throw "Unsupported MSI scope '$InstallScope'."
        }
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$binaryFullPath = (Resolve-Path -LiteralPath $BinaryPath).Path
$readmePath = Join-Path $repoRoot "README.md"
$licensePath = Join-Path $repoRoot "LICENSE"

if (-not (Test-Path -LiteralPath $readmePath)) {
    throw "Missing README.md at '$readmePath'."
}

if (-not (Test-Path -LiteralPath $licensePath)) {
    throw "Missing LICENSE at '$licensePath'."
}

$outputFullPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDir))
New-Item -ItemType Directory -Force -Path $outputFullPath | Out-Null

$msiVersion = ConvertTo-MsiVersion -Tag $VersionTag
$scopeInfo = Get-ScopeMetadata -InstallScope $Scope
$packageName = "nono-$VersionTag-x86_64-pc-windows-msvc-$($scopeInfo.PackageSuffix).msi"
$wxsName = "nono-$($scopeInfo.PackageSuffix).wxs"
$wxsPath = Join-Path $outputFullPath $wxsName
$msiPath = Join-Path $outputFullPath $packageName

$wxsContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package
      Name="nono"
      Manufacturer="$Manufacturer"
      Version="$msiVersion"
      UpgradeCode="$($scopeInfo.UpgradeCode)"
      Scope="$($scopeInfo.PackageScope)">
    <SummaryInformation
        Description="nono Windows native installer ($($scopeInfo.ScopeLabel))"
        Manufacturer="$Manufacturer" />
    <MajorUpgrade
        DowngradeErrorMessage="A newer version of [ProductName] is already installed." />
    <MediaTemplate EmbedCab="yes" CompressionLevel="high" />
    <Property Id="ARPCOMMENTS" Value="nono Windows native installer ($($scopeInfo.ScopeLabel))" />
    <Property Id="ARPCONTACT" Value="$Manufacturer" />
    <Property Id="ARPURLHELP" Value="https://docs.nono.sh/cli/getting_started/installation" />
    <Property Id="ARPURLINFOABOUT" Value="https://github.com/always-further/nono" />
    <Property Id="ARPURLUPDATEINFO" Value="https://github.com/always-further/nono/releases" />
    <Property Id="ARPNOMODIFY" Value="1" />
    <Property Id="ARPNOREPAIR" Value="1" />
    <Feature Id="MainFeature" Title="nono" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>
  </Package>

  <Fragment>
$($scopeInfo.DirectoryXml)
  </Fragment>

  <Fragment>
    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="cmpNonoExe" Guid="*">
        <File Id="filNonoExe" Source="$binaryFullPath" KeyPath="yes" />
      </Component>
      <Component Id="cmpReadme" Guid="*">
        <File Id="filReadme" Source="$readmePath" Name="README.md" KeyPath="yes" />
      </Component>
      <Component Id="cmpLicense" Guid="*">
        <File Id="filLicense" Source="$licensePath" Name="LICENSE" KeyPath="yes" />
      </Component>
      <Component Id="cmpPath" Guid="*">
        <RegistryValue
            Root="$($scopeInfo.RegistryRoot)"
            Key="Software\always-further\nono\$Scope"
            Name="InstallDir"
            Type="string"
            Value="[INSTALLFOLDER]"
            KeyPath="yes" />
        <Environment
            Id="EnvPath"
            Name="PATH"
            Action="set"
            Part="last"
            Permanent="no"
            System="$($scopeInfo.SystemPath)"
            Value="[INSTALLFOLDER]" />
      </Component>
    </ComponentGroup>
  </Fragment>
</Wix>
"@

Set-Content -LiteralPath $wxsPath -Value $wxsContent -Encoding utf8NoBOM

if ($EmitOnly) {
    Write-Host "Wrote WiX source to $wxsPath"
    return
}

$wix = Get-Command wix -ErrorAction SilentlyContinue
if ($null -eq $wix) {
    throw "WiX CLI was not found on PATH. Install WiX v4 and rerun the packaging script."
}

if (Test-Path -LiteralPath $msiPath) {
    Remove-Item -LiteralPath $msiPath -Force
}

& $wix.Source build $wxsPath -arch x64 -out $msiPath
if ($LASTEXITCODE -ne 0) {
    throw "WiX failed while building '$msiPath'."
}

Write-Host "Built MSI package: $msiPath"
