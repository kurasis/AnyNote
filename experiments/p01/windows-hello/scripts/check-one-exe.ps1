# Build verification only. The owner needs only the executable.
$ErrorActionPreference='Stop'
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$installation=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'MSVC installation not found' }
$developer=Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$exe=(Resolve-Path target/x86_64-pc-windows-msvc/release/anynote-p01-windows-hello.exe).Path
$command="`"$developer`" -arch=x64 -host_arch=x64 >nul && dumpbin /dependents `"$exe`""
$dependencies=& cmd.exe /d /c $command
if ($LASTEXITCODE -ne 0) { throw 'PE dependency inspection failed' }
$dependencies | Out-File artifacts/pe-dependencies.txt -Encoding utf8
if (($dependencies -join "`n") -match '(?im)\b(?:vcruntime\d\S*|msvcp\d\S*|libsodium\S*)\.dll\b') { throw 'Executable needs an unbundled non-system DLL' }
if (($dependencies -join "`n") -notmatch '(?i)kernel32\.dll') { throw 'Incomplete PE import observation' }
