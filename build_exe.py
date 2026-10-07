#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BanTV Drop — воспроизводимая сборка EXE. python build_exe.py"""
import os, subprocess, sys, shutil, traceback
from pathlib import Path

BASE=Path(__file__).resolve().parent
ICON=BASE/"logo.ico"; HTML=BASE/"index.html"; APP=BASE/"app.py"
PS1_CERT=BASE/"make_cert.ps1"; PS1_SIGN=BASE/"sign_exe.ps1"
PFX=BASE/"bantv_sign.pfx"
EXE=BASE/"dist"/"BanTV Drop.exe"          # <-- ОДИН файл

PS1_CERT_TEXT=r'''
$ErrorActionPreference="Stop"
$base=$PSScriptRoot
$pfx=Join-Path $base "bantv_sign.pfx"; $cer=Join-Path $base "bantv_sign.cer"; $pass=$env:BANTV_PFX_PASS
if(-not $pass){throw "Set BANTV_PFX_PASS before creating a development certificate"}
$cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=BanTV Drop, O=BanTV, C=RU" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) -CertStoreLocation "Cert:\CurrentUser\My"
$sec=ConvertTo-SecureString -String $pass -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $sec | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
Write-Host "CERT OK"
'''
PS1_SIGN_TEXT=r'''
param([string]$Exe,[string]$Pfx,[string]$Pass=$env:BANTV_PFX_PASS)
if(-not $Exe){$Exe=Join-Path $PSScriptRoot "dist\BanTV Drop.exe"}
if(-not $Pfx){$Pfx=Join-Path $PSScriptRoot "bantv_sign.pfx"}
if(-not (Test-Path $Exe)){Write-Host "EXE not found";exit 1}
if(-not (Test-Path $Pfx)){Write-Host "PFX not found";exit 1}
$cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx,$Pass)
Set-AuthenticodeSignature -FilePath $Exe -Certificate $cert -HashAlgorithm SHA256 | Out-Null
Write-Host "SIGNED"
'''

def log(*a): print("[build]",*a)
def ps(): return shutil.which("powershell") or "powershell.exe"
def run_list(cmd,warn=True):
    log(">", " ".join(map(str,cmd)))
    r=subprocess.run([str(c) for c in cmd],cwd=str(BASE))
    if r.returncode!=0 and not warn: raise SystemExit(f"code {r.returncode}")
    return r.returncode

def step_cert():
    # Самоподписанный сертификат не делает релиз доверенным. Сертификат и пароль
    # поставляются извне (например, секретом CI), а не генерируются и не импортируются в Root.
    if PFX.exists() and os.environ.get("BANTV_PFX_PASS"): log("release certificate found")
    else: log("unsigned development build (set BANTV_PFX_PASS and provide PFX to sign)")

def step_build():
    req=BASE/"requirements.txt"
    run_list([sys.executable,"-m","pip","install","--requirement",str(req)],warn=False)
    cmd=[sys.executable,"-m","PyInstaller","--noconfirm","--clean","--onefile","--noconsole","--name","BanTV Drop"]
    if ICON.exists(): cmd+=["--icon",str(ICON),"--add-data",f"{ICON};."]
    if HTML.exists(): cmd+=["--add-data",f"{HTML};."]
    cmd+=[str(APP)]
    if run_list(cmd,warn=True)!=0:
        pi=shutil.which("pyinstaller")
        if pi:
            c2=[pi,"--noconfirm","--clean","--onefile","--noconsole","--name","BanTV Drop"]
            if ICON.exists(): c2+=["--icon",str(ICON),"--add-data",f"{ICON};."]
            if HTML.exists(): c2+=["--add-data",f"{HTML};."]
            c2+=[str(APP)]; run_list(c2,warn=False)
        else: raise SystemExit("PyInstaller not found")

def step_sign():
    pfx_pass=os.environ.get("BANTV_PFX_PASS")
    if not (EXE.exists() and PFX.exists() and pfx_pass): log("sign skipped"); return
    if not PS1_SIGN.exists(): PS1_SIGN.write_text(PS1_SIGN_TEXT,encoding="utf-8-sig")
    if shutil.which("signtool"):
        run_list(["signtool","sign","/f",str(PFX),"/p",pfx_pass,"/fd","SHA256",str(EXE)],warn=False)
    else:
        r=subprocess.run([ps(),"-NoProfile","-File",str(PS1_SIGN),
                          "-Exe",str(EXE),"-Pfx",str(PFX),"-Pass",pfx_pass],cwd=str(BASE))
        if r.returncode: raise SystemExit("code signing failed")
    log("signed")

def main():
    log("base:",BASE)
    log("[1/3] cert…");  step_cert()
    log("[2/3] build ONEFILE…"); step_build()
    log("[3/3] sign…");  step_sign()
    log("DONE:", EXE if EXE.exists() else "dist/BanTV Drop.exe")

if __name__=="__main__":
    try: main()
    except Exception:
        traceback.print_exc(); raise
    finally:
        if sys.stdin.isatty(): input("\nНажмите Enter…")
