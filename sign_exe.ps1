# sign_exe.ps1 — подпись EXE (без Get-PfxCertificate -Password)
param([string]$Exe, [string]$Pfx, [string]$Pass=$env:BANTV_PFX_PASS)
if(-not $Exe){ $Exe = Join-Path $PSScriptRoot "dist\BanTV Drop.exe" }
if(-not $Pfx){ $Pfx = Join-Path $PSScriptRoot "bantv_sign.pfx" }
if(-not (Test-Path $Exe)){ Write-Host "EXE не найден: $Exe"; exit 1 }
if(-not (Test-Path $Pfx)){ Write-Host "PFX не найден: $Pfx (сначала make_cert.ps1)"; exit 1 }
if(-not $Pass){ Write-Host "Set BANTV_PFX_PASS"; exit 1 }
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $Pass)
Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert -HashAlgorithm SHA256 | Out-Null
Write-Host "SIGNED: $Exe"
