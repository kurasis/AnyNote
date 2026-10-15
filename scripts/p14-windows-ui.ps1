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
 public static bool FileNameEdit(IntPtr h){
  if(ClassOf(h)!="Edit")return false;int id=GetDlgCtrlID(h);return id==1148||id==1152||id==1001;
 }
 [StructLayout(LayoutKind.Sequential)] public struct RECT {public int left,top,right,bottom;}
 [StructLayout(LayoutKind.Sequential)] public struct GUIINFO {public uint cbSize,flags;public IntPtr active,focus,capture,menuOwner,moveSize,caret;public RECT caretRect;}
 [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint id,ref GUIINFO info);
 [DllImport("user32.dll")] public static extern bool IsChild(IntPtr parent,IntPtr child);
 public static string FileInputStage="NOT_STARTED";
 static INPUT Key(ushort key,ushort scan,uint flags){var p=new INPUT();p.type=1;p.data.keyboard.key=key;p.data.keyboard.scan=scan;p.data.keyboard.flags=flags;return p;}
 static bool ForegroundOwned(uint pid){uint p;GetWindowThreadProcessId(GetForegroundWindow(),out p);return p==pid;}
 static bool FocusControl(IntPtr dialog,IntPtr h,uint pid){
  if(!ForegroundOwned(pid))return false;SetForegroundWindow(dialog);UIntPtr result;
  if(SendMessageTimeout(dialog,0x28,h,(IntPtr)1,2,5000,out result)==IntPtr.Zero)return false;
  uint owner;uint tid=GetWindowThreadProcessId(h,out owner);if(owner!=pid)return false;
  for(int n=0;n<20;n++){var info=new GUIINFO();info.cbSize=(uint)Marshal.SizeOf(typeof(GUIINFO));if(GetGUIThreadInfo(tid,ref info)&&(info.focus==h||IsChild(h,info.focus)))return ForegroundOwned(pid);System.Threading.Thread.Sleep(50);}return false;
 }
 static bool WaitText(IntPtr h,string expected){
  for(int n=0;n<40;n++){var b=new StringBuilder(32768);UIntPtr result;if(ReadText(h,0xD,(IntPtr)b.Capacity,b,2,5000,out result)==IntPtr.Zero)return false;if(b.ToString()==expected)return true;System.Threading.Thread.Sleep(50);}return false;
 }
 public static bool SetFileName(IntPtr dialog,IntPtr h,IntPtr accept,string text,uint pid){
  if(text.Length==0||text.Length>32766||text.IndexOfAny(new char[]{(char)0,(char)10,(char)13})>=0)return false;
  FileInputStage="FOCUS_FILENAME";if(!FocusControl(dialog,h,pid))return false;UIntPtr result;
  FileInputStage="CLEAR_FILENAME";if(SendMessageTimeout(h,0xB1,IntPtr.Zero,(IntPtr)(-1),2,5000,out result)==IntPtr.Zero)return false;
  var erase=new INPUT[]{Key(8,0,0),Key(8,0,2)};if(SendInput(2,erase,Marshal.SizeOf(typeof(INPUT)))!=2||!WaitText(h,""))return false;
  FileInputStage="TYPE_FILENAME";if(!ForegroundOwned(pid))return false;var input=new List<INPUT>();foreach(char c in text){input.Add(Key(0,c,4));input.Add(Key(0,c,6));}var values=input.ToArray();
  if(SendInput((uint)values.Length,values,Marshal.SizeOf(typeof(INPUT)))!=(uint)values.Length||!WaitText(h,text))return false;
  FileInputStage="COMMIT_FILENAME";if(!FocusControl(dialog,accept,pid))return false;FileInputStage="READY";return true;
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
   $fileEdits=@();$accept=[IntPtr]::Zero
   foreach($child in [AnyNoteTestWindow]::OwnedChildren($dialog,[uint32]$ProcessId)){
    if(![AnyNoteTestWindow]::IsWindowVisible($child) -or ![AnyNoteTestWindow]::IsWindowEnabled($child)){continue}
    if([AnyNoteTestWindow]::FileNameEdit($child)){$fileEdits+=@($child)}
    if([AnyNoteTestWindow]::ClassOf($child) -eq 'Button' -and [AnyNoteTestWindow]::GetDlgCtrlID($child) -eq 1){$accept=$child}
   }
   if($fileEdits.Count -gt 1 -and $accept -ne [IntPtr]::Zero){throw 'Ambiguous owned native filename edit'}
   if($fileEdits.Count -eq 1 -and $accept -ne [IntPtr]::Zero){
    $fileEdit=$fileEdits[0]
    if(![AnyNoteTestWindow]::SetFileName($dialog,$fileEdit,$accept,$Value,[uint32]$ProcessId)){throw ('Owned native filename input failed: '+[AnyNoteTestWindow]::FileInputStage)}
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
$nativeEdits=@()
foreach($dialog in [AnyNoteTestWindow]::OwnedWindows([uint32]$ProcessId)){
 if([AnyNoteTestWindow]::ClassOf($dialog) -ne '#32770' -or ![AnyNoteTestWindow]::IsWindowVisible($dialog)){continue}
 foreach($child in [AnyNoteTestWindow]::OwnedChildren($dialog,[uint32]$ProcessId)){
  if([AnyNoteTestWindow]::ClassOf($child) -eq 'Edit' -and [AnyNoteTestWindow]::IsWindowVisible($child)){
   $parent=[AnyNoteTestWindow]::GetParent($child);$nativeEdits+=@{id=[AnyNoteTestWindow]::GetDlgCtrlID($child);parent_id=[AnyNoteTestWindow]::GetDlgCtrlID($parent);parent_class=[AnyNoteTestWindow]::ClassOf($parent);enabled=[AnyNoteTestWindow]::IsWindowEnabled($child)}
  }
 }
}
[Console]::Error.WriteLine(('OWNED_NATIVE_FILENAME_EDITS '+($nativeEdits|ConvertTo-Json -Compress)))
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
