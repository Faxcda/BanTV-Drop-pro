# make_cert.ps1 — самоподписанный CodeSigning-сертификат
$ErrorActionPreference="Stop"
$base=$PSScriptRoot
$pfx=Join-Path $base "bantv_sign.pfx"
$cer=Join-Path $base "bantv_sign.cer"
$pass=$env:BANTV_PFX_PASS
if(-not $pass){ throw "Set BANTV_PFX_PASS before creating a development certificate" }
$cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=BanTV Drop, O=BanTV, C=RU" `
  -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
  -NotAfter (Get-Date).AddYears(5) -CertStoreLocation "Cert:\CurrentUser\My"
$sec=ConvertTo-SecureString -String $pass -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec | Out-Null
Export-Certificate   -Cert $cert -FilePath $cer | Out-Null
Write-Host "CERT OK: $pfx"
