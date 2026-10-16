# Read-only Restart Manager resource-user probe for a disposable CI file.
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
if($env:GITHUB_ACTIONS -ne 'true'){throw 'Synthetic Windows Actions runner required'}
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class AnyNoteRestartManager {
 [StructLayout(LayoutKind.Sequential)] public struct UNIQUE_PROCESS {public uint pid; public System.Runtime.InteropServices.ComTypes.FILETIME started;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct PROCESS_INFO {
  public UNIQUE_PROCESS process;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string name;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=64)] public string service;
  public uint type,status,session;
  [MarshalAs(UnmanagedType.Bool)] public bool restartable;
 }
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] static extern int RmStartSession(out uint session,uint flags,StringBuilder key);
 [DllImport("rstrtmgr.dll",CharSet=CharSet.Unicode)] static extern int RmRegisterResources(uint session,uint files,string[] paths,uint apps,IntPtr processes,uint services,IntPtr names);
 [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint session,out uint needed,ref uint count,[In,Out] PROCESS_INFO[] processes,ref uint reasons);
 [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint session);
 public static uint[] Users(string path){
  uint session;int code=RmStartSession(out session,0,new StringBuilder(33));if(code!=0)throw new Exception("RM_START_"+code);
  try {
   code=RmRegisterResources(session,1,new string[]{path},0,IntPtr.Zero,0,IntPtr.Zero);if(code!=0)throw new Exception("RM_REGISTER_"+code);
   uint needed,count=0,reasons=0;code=RmGetList(session,out needed,ref count,null,ref reasons);
   if(code==0)return new uint[0];if(code!=234)throw new Exception("RM_LIST_"+code);
   for(int attempt=0;attempt<5;attempt++){
    count=needed;var rows=new PROCESS_INFO[count];code=RmGetList(session,out needed,ref count,rows,ref reasons);
    if(code==234)continue;if(code!=0)throw new Exception("RM_LIST_"+code);
    var ids=new uint[count];for(int i=0;i<count;i++)ids[i]=rows[i].process.pid;return ids;
   }
   throw new Exception("RM_LIST_CHANGING");
  }finally{RmEndSession(session);}
 }
}
'@
[Console]::Write((ConvertTo-Json -Compress -InputObject @([AnyNoteRestartManager]::Users((Resolve-Path $Path).Path))))
