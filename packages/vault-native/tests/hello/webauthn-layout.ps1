# Test-only MSVC compilation against a pinned official API-9 header.
$ErrorActionPreference = 'Stop'
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'MSVC installation not found' }
$developer = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$temporary = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() }
$out = Join-Path $temporary 'passkey-webauthn-abi'
New-Item -ItemType Directory -Force $out | Out-Null
$exe = Join-Path $out 'layout.exe'
$obj = Join-Path $out 'layout.obj'
$reference = Join-Path $out 'layout.txt'
$command = "`"$developer`" -arch=x64 -host_arch=x64 >nul && cl /nologo /W4 /WX /std:c11 tests\hello\webauthn-layout.c /Fo:`"$obj`" /Fe:`"$exe`" && `"$exe`" > `"$reference`""
& cmd.exe /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'Official header ABI probe failed' }
if ((Get-Content $reference).Count -lt 100) { throw 'Incomplete ABI reference' }
$env:WEBAUTHN_ABI_REFERENCE = $reference
if ($env:GITHUB_ENV) { "WEBAUTHN_ABI_REFERENCE=$reference" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8 }
