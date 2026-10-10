# SPDX-License-Identifier: GPL-3.0-only
# Content-free capture; native state changes occur only for the explicitly selected operation.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Probe,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSource,
    [ValidateSet('capabilities','roundtrip','enroll','unlock','cleanup')][string]$Operation='capabilities',
    [ValidateSet('physical','hosted')][string]$EnvironmentKind='physical',
    [string]$OutputDirectory='P01-physical-results'
)
$ErrorActionPreference='Stop'
$probePath=(Resolve-Path -LiteralPath $Probe).Path
$actualHash=(Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
if($actualHash -ne $ExpectedSha256.ToLowerInvariant()){throw 'Probe hash mismatch; no probe operation executed'}
$capText=(& $probePath capabilities | Out-String)
$capExit=$LASTEXITCODE
if($capExit -ne 0){throw 'Capability capture failed; do not proceed with enrollment'}
$cap=$capText | ConvertFrom-Json
if($cap.source_commit -ne $ExpectedSource){throw 'Probe source mismatch; no enrollment/unlock executed'}
if($cap.native_objects_created -ne $false){throw 'Capability report does not establish no object creation'}
$os=Get-CimInstance Win32_OperatingSystem
$machine=Get-CimInstance Win32_ComputerSystem
$version=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$outcome='NOT RUN'
$nativeExit=$null
$nativeText=$null
if($Operation -eq 'capabilities'){
    $nativeText=$capText;$nativeExit=$capExit;$outcome=$cap.report.outcome
}elseif($Operation -ne 'cleanup' -and $cap.report.eligible -ne $true){
    $outcome='BLOCKED: capability gate; no selected native operation executed'
}else{
    # Expected cancellation/unavailability can return nonzero; always preserve it.
    $ErrorActionPreference='Continue'
    try{$nativeText=(& $probePath $Operation 2>&1 | Out-String);$nativeExit=$LASTEXITCODE}
    finally{$ErrorActionPreference='Stop'}
    $outcome=if($nativeExit -eq 0){'NATIVE_OPERATION_REPORTED_SUCCESS'}else{'NATIVE_OPERATION_FAILED_OR_UNAVAILABLE'}
}
$record=[ordered]@{
    format_version=1; date_utc=[DateTime]::UtcNow.ToString('o'); environment_kind=$EnvironmentKind
    source_commit=$ExpectedSource; executable_sha256=$actualHash; operation=$Operation
    os=[ordered]@{caption=$os.Caption;version=$os.Version;build=$os.BuildNumber;architecture=$os.OSArchitecture;display_version=$version.DisplayVersion;ubr=$version.UBR}
    hardware=[ordered]@{manufacturer=$machine.Manufacturer;model=$machine.Model;physical_memory_bytes=$machine.TotalPhysicalMemory}
    capability=$cap; operation_outcome=$outcome; native_exit_code=$nativeExit; native_output=$nativeText
    physical_acceptance=$false
    operator_observations='Record actual prompts, deliberate cancellation/lock and cleanup in the trial template; native success alone does not certify G1.'
}
[IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($OutputDirectory)) | Out-Null
$recordPath=Join-Path $OutputDirectory ('trial-'+[Guid]::NewGuid().ToString('N')+'.json')
[IO.File]::WriteAllText([IO.Path]::GetFullPath($recordPath),($record | ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
Write-Output ('Recorded '+$Operation+': '+$outcome+'; '+$recordPath)
if($null -ne $nativeExit -and $nativeExit -ne 0){exit 2}
