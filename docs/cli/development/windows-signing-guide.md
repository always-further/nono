# Windows Signing Guide

This guide covers the Authenticode signing setup required to produce signed Windows release artifacts.

## Required GitHub Actions secrets

Both secrets must be set as repository secrets before the release workflow can produce signed artifacts.

| Secret | Description | Source |
|--------|-------------|--------|
| `WINDOWS_SIGNING_CERT` | Base64-encoded PFX certificate (certificate + private key) | Export your code-signing cert to PFX, then run: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))` |
| `WINDOWS_SIGNING_CERT_PASSWORD` | Password protecting the PFX file | Set when exporting the PFX |

Set these at **Settings → Secrets and variables → Actions → New repository secret** in the GitHub repository.

## What gets signed

The release workflow signs these artifacts before uploading them:

- `nono.exe` — the compiled binary
- `nono-vX.Y.Z-x86_64-pc-windows-msvc-machine.msi` — the per-machine MSI installer
- `nono-vX.Y.Z-x86_64-pc-windows-msvc-user.msi` — the per-user MSI installer

The `.zip` artifact (`nono-vX.Y.Z-x86_64-pc-windows-msvc.zip`) contains the already-signed `nono.exe` — it is assembled after signing.

## Verifying signatures

To verify an Authenticode signature on a downloaded artifact:

```powershell
$sig = Get-AuthenticodeSignature -FilePath "nono.exe"
$sig.SignatureStatus
# Expected output: Valid

$sig.SignerCertificate.Subject
# Expected output: CN=<your organization name>, ...
```

For MSI artifacts, pass the MSI path:

```powershell
Get-AuthenticodeSignature -FilePath "nono-v0.2.0-x86_64-pc-windows-msvc-machine.msi" |
    Select-Object SignatureStatus, SignerCertificate
```

`SignatureStatus` must be `Valid`. Any other status (`NotSigned`, `HashMismatch`, `UnknownError`) means the artifact should not be distributed.

## What happens when secrets are absent

If either `WINDOWS_SIGNING_CERT` or `WINDOWS_SIGNING_CERT_PASSWORD` is missing from repository secrets, the release workflow **fails immediately** with this error:

```
WINDOWS_SIGNING_CERT and WINDOWS_SIGNING_CERT_PASSWORD must be set.
Set these repository secrets before releasing Windows artifacts.
See docs/cli/development/windows-signing-guide.md.
```

No artifacts are uploaded. The workflow does not silently skip signing and produce unsigned artifacts. This is intentional — unsigned Windows artifacts cannot be distributed.

## Generating a test certificate (development only)

To test the signing workflow without a production code-signing certificate, generate a self-signed certificate:

```powershell
# Generate a self-signed certificate for local testing only
$cert = New-SelfSignedCertificate `
    -Subject "CN=nono Test Signing" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -Type CodeSigningCert `
    -HashAlgorithm SHA256

# Export to PFX with a password
$password = ConvertTo-SecureString -String "TestPassword123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "nono-test.pfx" -Password $password

# Encode to base64 for use as WINDOWS_SIGNING_CERT secret
$base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("nono-test.pfx"))
Write-Host $base64

# Clean up local cert and PFX after setting secrets
Remove-Item "nono-test.pfx" -Force
Remove-Item -Path $cert.PSPath -Force
```

**Do not use self-signed certificates in production releases.** Self-signed certificates cause Windows SmartScreen warnings. Production releases require a certificate from a trusted CA (DigiCert, Sectigo, or similar) enrolled in the Microsoft Trusted Root Program.

## Signing implementation

Signing is performed by `scripts/sign-windows-artifacts.ps1`. The script:

1. Decodes `WINDOWS_SIGNING_CERT` from base64 to a PFX file
2. Imports the certificate into `Cert:\CurrentUser\My`
3. Calls `signtool.exe sign /fd sha256 /sha1 <thumbprint> /t http://timestamp.digicert.com <artifact>` for each artifact
4. Calls `signtool.exe verify /pa <artifact>` to confirm each signature
5. Removes the certificate from the store and deletes the PFX temp file

The script requires `signtool.exe` on PATH, which is available on GitHub Actions `windows-latest` runners via the pre-installed Windows SDK.
