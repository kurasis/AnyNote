# CI-owned real Windows dialog/lifecycle automation. Never used by the product.
param([ValidateSet('file','consent','foreground','wts-lock','wts-unlock','memory','clipboard-read','clipboard-other','installed-version','input')][string]$Operation,[int]$ProcessId,[string]$Value)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Synthetic Windows Actions runner required'}
if($Operation -eq 'installed-version'){[Console]::Write([Diagnostics.FileVersionInfo]::GetVersionInfo($Value).ProductVersion);exit}
if($Operation -eq 'clipboard-read'){[Console]::Write([string](Get-Clipboard -Raw));exit}
if($Operation -eq 'clipboard-other'){Set-Clipboard -Value 'P14 synthetic other application copy';exit}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;using System.Collections.Generic;using System.Text;
public static class AnyNoteTestWindow {
 [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n,INPUT[] inputs,int size);
 [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {public ushort key,scan;public uint flags,time;public UIntPtr extra;}
 [StructLayout(LayoutKind.Explicit,Size=32)] public struct INPUTUNION {[FieldOffset(0)] public KEYBDINPUT keyboard;}
 [StructLayout(LayoutKind.Sequential)] public struct INPUT {public uint type;public INPUTUNION data;}
 public delegate bool EnumWindow(IntPtr h,IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindow cb,IntPtr l);
 [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h,StringBuilder s,int n);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll", SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr h,uint m,IntPtr w,IntPtr l,uint flags,uint timeout,out UIntPtr result);
 public static IntPtr[] OwnedWindows(uint pid){var a=new List<IntPtr>();EnumWindows((h,l)=>{uint p;GetWindowThreadProcessId(h,out p);if(p==pid)a.Add(h);return true;},IntPtr.Zero);return a.ToArray();}
 public static string ClassOf(IntPtr h){var b=new StringBuilder(256);GetClassName(h,b,256);return b.ToString();}
 public static string TitleOf(IntPtr h){var b=new StringBuilder(256);GetWindowText(h,b,256);return b.ToString();}
 [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h,EnumWindow cb,IntPtr l);
 [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
 [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
 [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr SendText(IntPtr h,uint m,IntPtr w,string text,uint flags,uint timeout,out UIntPtr result);
 [DllImport("user32.dll",EntryPoint="SendMessageTimeoutW",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr ReadText(IntPtr h,uint m,IntPtr w,StringBuilder text,uint flags,uint timeout,out UIntPtr result);
 public static IntPtr[] OwnedChildren(IntPtr root,uint pid){var a=new List<IntPtr>();EnumChildWindows(root,(h,l)=>{uint p;GetWindowThreadProcessId(h,out p);if(p==pid)a.Add(h);return true;},IntPtr.Zero);return a.ToArray();}
 public static bool FileNameEdit(IntPtr h,IntPtr root){
  if(ClassOf(h)!="Edit")return false;int id=GetDlgCtrlID(h);if(id==1148||id==1152)return true;if(id!=1001)return false;
  var p=GetParent(h);for(int n=0;n<8&&p!=IntPtr.Zero&&p!=root;n++,p=GetParent(p)){if(GetDlgCtrlID(p)==1148||ClassOf(p)=="AppControlHost")return true;}return false;
 }
 public static bool SetFileName(IntPtr h,string text){
  if(text.Length==0||text.Length>32766)return false;UIntPtr result;
  if(SendText(h,0xC,IntPtr.Zero,text,2,5000,out result)==IntPtr.Zero||result==UIntPtr.Zero)return false;
  var b=new StringBuilder(text.Length+1);return ReadText(h,0xD,(IntPtr)b.Capacity,b,2,5000,out result)!=IntPtr.Zero&&b.ToString()==text;
 }
 public static bool NeutralInput(){var a=new INPUT[2];a[0].type=a[1].type=1;a[0].data.keyboard.key=a[1].data.keyboard.key=0x10;a[1].data.keyboard.flags=2;return SendInput(2,a,Marshal.SizeOf(typeof(INPUT)))==2;}

}
'@
if($Operation -eq 'memory'){
 $all=Get-CimInstance Win32_Process;$ids=[Collections.Generic.HashSet[int]]::new();[void]$ids.Add($ProcessId)
 do{$changed=$false;foreach($p in $all){if($ids.Contains([int]$p.ParentProcessId) -and !$ids.Contains([int]$p.ProcessId)){[void]$ids.Add([int]$p.ProcessId);$changed=$true}}}while($changed)
 $rows=@()
 foreach($id in $ids){
  $p=Get-Process -Id $id -ErrorAction SilentlyContinue
  if($p){
   $rows+=@{pid=$id;kind=$(if($id -eq $ProcessId){'native'}elseif($p.ProcessName -eq 'msedgewebview2'){'webview2'}elseif($p.ProcessName -eq 'node'){'helper'}else{'other'});peak_working_set_bytes=$p.PeakWorkingSet64;working_set_bytes=$p.WorkingSet64}
  }
 }
 $rows|ConvertTo-Json -Compress;exit
}
$p=Get-Process -Id $ProcessId
$window=$p.MainWindowHandle
if($window -eq [IntPtr]::Zero){throw 'Real main HWND required'}
# Real OS input simulates an active synthetic operator. It does not disable idle policy.
if($Operation -eq 'input'){
 [void][AnyNoteTestWindow]::SetForegroundWindow($window)
 [uint32]$foregroundOwner=0;[void][AnyNoteTestWindow]::GetWindowThreadProcessId([AnyNoteTestWindow]::GetForegroundWindow(),[ref]$foregroundOwner)
 if($foregroundOwner -ne $ProcessId -or [IntPtr]::Size -ne 8 -or ![AnyNoteTestWindow]::NeutralInput()){throw 'Owned synthetic operator input failed'}
 exit
}
if($Operation -eq 'foreground'){[void][AnyNoteTestWindow]::SetForegroundWindow($window);exit}
# Software messages test the installed handler. They are not a physical Win+L trial.
if($Operation -eq 'wts-lock'){[void][AnyNoteTestWindow]::SendMessage($window,0x2B1,[IntPtr]7,[IntPtr]0);exit}
if($Operation -eq 'wts-unlock'){[void][AnyNoteTestWindow]::SendMessage($window,0x2B1,[IntPtr]8,[IntPtr]0);exit}
$deadline=(Get-Date).AddSeconds(45)
do{
 if($Operation -eq 'file'){
  foreach($dialog in [AnyNoteTestWindow]::OwnedWindows([uint32]$ProcessId)){
   if([AnyNoteTestWindow]::ClassOf($dialog) -ne '#32770' -or ![AnyNoteTestWindow]::IsWindowVisible($dialog)){continue}
   $fileEdit=[IntPtr]::Zero;$accept=[IntPtr]::Zero
   foreach($child in [AnyNoteTestWindow]::OwnedChildren($dialog,[uint32]$ProcessId)){
    if(![AnyNoteTestWindow]::IsWindowVisible($child) -or ![AnyNoteTestWindow]::IsWindowEnabled($child)){continue}
    if([AnyNoteTestWindow]::FileNameEdit($child,$dialog)){$fileEdit=$child}
    if([AnyNoteTestWindow]::ClassOf($child) -eq 'Button' -and [AnyNoteTestWindow]::GetDlgCtrlID($child) -eq 1){$accept=$child}
   }
   if($fileEdit -ne [IntPtr]::Zero -and $accept -ne [IntPtr]::Zero){
    if(![AnyNoteTestWindow]::SetFileName($fileEdit,$Value)){throw 'Owned native filename edit failed'}
    [UIntPtr]$fileResult=[UIntPtr]::Zero
    if([AnyNoteTestWindow]::SendMessageTimeout($accept,0xF5,[IntPtr]::Zero,[IntPtr]::Zero,2,5000,[ref]$fileResult) -eq [IntPtr]::Zero){throw 'Owned native file button did not respond'}
    $closeDeadline=(Get-Date).AddSeconds(5)
    while([AnyNoteTestWindow]::IsWindowVisible($dialog) -and (Get-Date) -lt $closeDeadline){Start-Sleep -Milliseconds 100}
    if([AnyNoteTestWindow]::IsWindowVisible($dialog)){throw 'Owned file selection did not close its native dialog'}
    exit
   }
  }
 }
 if($Operation -eq 'consent'){
  foreach($dialog in [AnyNoteTestWindow]::OwnedWindows([uint32]$ProcessId)){
   $yes=[AnyNoteTestWindow]::GetDlgItem($dialog,6);$no=[AnyNoteTestWindow]::GetDlgItem($dialog,7)
   if([AnyNoteTestWindow]::ClassOf($dialog) -eq '#32770' -and [AnyNoteTestWindow]::TitleOf($dialog).StartsWith('AnyNote') -and [AnyNoteTestWindow]::IsWindowVisible($dialog) -and $yes -ne [IntPtr]::Zero -and $no -ne [IntPtr]::Zero -and [AnyNoteTestWindow]::ClassOf($yes) -eq 'Button' -and [AnyNoteTestWindow]::IsWindowVisible($yes) -and [AnyNoteTestWindow]::IsWindowEnabled($yes)){
    [UIntPtr]$consentResult=[UIntPtr]::Zero;if([AnyNoteTestWindow]::SendMessageTimeout($yes,0xF5,[IntPtr]::Zero,[IntPtr]::Zero,2,5000,[ref]$consentResult) -eq [IntPtr]::Zero){throw 'Owned native consent did not respond'};exit
   }
  }
 }
 # UI Automation's desktop-child PID query can omit owned modal dialogs.
 # Bind providers to actual visible HWNDs from this exact disposable process.
 $windows=@(foreach($ownedWindow in [AnyNoteTestWindow]::OwnedWindows([uint32]$ProcessId)){
  if([AnyNoteTestWindow]::IsWindowVisible($ownedWindow)){
   try{[Windows.Automation.AutomationElement]::FromHandle($ownedWindow)}catch{}
  }
 })
 foreach($candidate in $windows){
  $controls=$candidate.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)
  if($Operation -eq 'file'){
   $edit=$null;$button=$null
   foreach($control in $controls){
    if($control.Current.ControlType -in @([Windows.Automation.ControlType]::Edit,[Windows.Automation.ControlType]::ComboBox) -and $control.Current.AutomationId -in @('1148','1001')){
     $valuePattern=$null;if($control.TryGetCurrentPattern([Windows.Automation.ValuePattern]::Pattern,[ref]$valuePattern) -and (!$edit -or $control.Current.AutomationId -eq '1148')){$edit=$control}
    }
    if($control.Current.ControlType -in @([Windows.Automation.ControlType]::Button,[Windows.Automation.ControlType]::SplitButton) -and $control.Current.AutomationId -eq '1'){$button=$control}
   }
   if($edit -and $button){$pattern=$edit.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern);$pattern.SetValue($Value);$button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();
    $dialogHandle=[IntPtr]$candidate.Current.NativeWindowHandle;$closeDeadline=(Get-Date).AddSeconds(5)
    while([AnyNoteTestWindow]::IsWindowVisible($dialogHandle) -and (Get-Date) -lt $closeDeadline){Start-Sleep -Milliseconds 100}
    if([AnyNoteTestWindow]::IsWindowVisible($dialogHandle)){throw 'Owned file selection did not close its native dialog'}
    exit}
  }else{
   foreach($control in $controls){if($control.Current.ControlType -eq [Windows.Automation.ControlType]::Button -and ($control.Current.AutomationId -eq '6' -or $control.Current.Name -in @('Yes','&Yes','Да','&Да'))){$control.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern).Invoke();exit}}
  }
 }
 Start-Sleep -Milliseconds 200
}while((Get-Date) -lt $deadline)
$dialogControls=@()
foreach($candidate in $windows){
 if($candidate.Current.ClassName -eq '#32770'){
  foreach($control in $candidate.FindAll([Windows.Automation.TreeScope]::Descendants,[Windows.Automation.Condition]::TrueCondition)){
   if($control.Current.AutomationId -in @('1','1001','1148','1152','FileNameControlHost')){$dialogControls+=@{id=$control.Current.AutomationId;type=$control.Current.ControlType.ProgrammaticName;class=$control.Current.ClassName;enabled=$control.Current.IsEnabled}}
  }
 }
}
[Console]::Error.WriteLine(('OWNED_FILE_CONTROL_TYPES '+($dialogControls|ConvertTo-Json -Compress)))
$native=@()
foreach($h in [AnyNoteTestWindow]::OwnedWindows([uint32]$ProcessId)){if(![AnyNoteTestWindow]::IsWindowVisible($h)){continue};$native+=@{class=[AnyNoteTestWindow]::ClassOf($h);visible=[AnyNoteTestWindow]::IsWindowVisible($h);enabled=[AnyNoteTestWindow]::IsWindowEnabled($h);yes=([AnyNoteTestWindow]::GetDlgItem($h,6) -ne [IntPtr]::Zero);no=([AnyNoteTestWindow]::GetDlgItem($h,7) -ne [IntPtr]::Zero)}}
[Console]::Error.WriteLine(('OWNED_WIN32_WINDOWS '+($native|ConvertTo-Json -Compress)))
throw 'Real native dialog not found'
