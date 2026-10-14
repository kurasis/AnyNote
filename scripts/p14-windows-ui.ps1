# CI-owned real Windows dialog/lifecycle automation. Never used by the product.
param([ValidateSet('file','consent','foreground','wts-lock','wts-unlock','memory','clipboard-read','clipboard-other','installed-version')][string]$Operation,[int]$ProcessId,[string]$Value)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Synthetic Windows Actions runner required'}
if($Operation -eq 'installed-version'){[Console]::Write([Diagnostics.FileVersionInfo]::GetVersionInfo($Value).ProductVersion);exit}
if($Operation -eq 'clipboard-read'){[Console]::Write([string](Get-Clipboard -Raw));exit}
if($Operation -eq 'clipboard-other'){Set-Clipboard -Value 'P14 synthetic other application copy';exit}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class AnyNoteTestWindow {
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
}
'@
if($Operation -eq 'memory'){
 $all=Get-CimInstance Win32_Process;$ids=[Collections.Generic.HashSet[int]]::new();[void]$ids.Add($ProcessId)
 do{$changed=$false;foreach($p in $all){if($ids.Contains([int]$p.ParentProcessId) -and !$ids.Contains([int]$p.ProcessId)){[void]$ids.Add([int]$p.ProcessId);$changed=$true}}}while($changed)
 $rows=@();foreach($id in $ids){$p=Get-Process -Id $id -ErrorAction SilentlyContinue;if($p){$rows+=@{pid=$id;kind=$(if($id -eq $ProcessId){'native'}elseif($p.ProcessName -eq 'msedgewebview2'){'webview2'}elseif($p.ProcessName -eq 'node'){'helper'}else{'other'});peak_working_set_bytes=$p.PeakWorkingSet64;working_set_bytes=$p.WorkingSet64}}
 $rows|ConvertTo-Json -Compress;exit
}
$p=Get-Process -Id $ProcessId
$window=$p.MainWindowHandle
if($window -eq [IntPtr]::Zero){throw 'Real main HWND required'}
if($Operation -eq 'foreground'){[void][AnyNoteTestWindow]::SetForegroundWindow($window);exit}
# Software messages test the installed handler. They are not a physical Win+L trial.
if($Operation -eq 'wts-lock'){[void][AnyNoteTestWindow]::SendMessage($window,0x2B1,[IntPtr]7,[IntPtr]0);exit}
if($Operation -eq 'wts-unlock'){[void][AnyNoteTestWindow]::SendMessage($window,0x2B1,[IntPtr]8,[IntPtr]0);exit}
$deadline=(Get-Date).AddSeconds(45)
do{
 $condition=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$ProcessId)
 $windows=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,$condition)
 foreach($candidate in $windows){
  $controls=$candidate.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
  if($Operation -eq 'file'){
   $edit=$null;$button=$null
   foreach($control in $controls){if($control.Current.ControlType -eq [Windows.Automation.ControlType]::Edit -and $control.Current.AutomationId -in @('1148','1001')){$edit=$control};if($control.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and $control.Current.AutomationId -eq '1'){$button=$control}}
   if($edit -and $button){$pattern=$edit.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern);$pattern.SetValue($Value);$button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();exit}
  }else{
   foreach($control in $controls){if($control.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and ($control.Current.AutomationId -eq '6' -or $control.Current.Name -in @('Yes','&Yes','Да','&Да'))){$control.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();exit}}
  }
 }
 Start-Sleep -Milliseconds 200
}while((Get-Date) -lt $deadline)
throw 'Real native dialog not found'
