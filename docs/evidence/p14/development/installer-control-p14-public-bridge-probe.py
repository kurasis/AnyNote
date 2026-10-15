import json,subprocess,hashlib,ctypes,time,os
from pathlib import Path
root=Path('.local/p14-installer-control').resolve();assert not root.exists();root.mkdir(parents=True);(root/'owner.json').write_text(json.dumps({'purpose':'P14 public NSIS installer mode diagnosis','source_commit':'72daa1ec25f94738b4b4479aa36983a3fa41010d'}))
manifest=json.loads(Path('artifacts/p14/ui-diagnostic-binaries.json').read_text());assert manifest['source_commit']=='72daa1ec25f94738b4b4479aa36983a3fa41010d'
for v in manifest['binaries'].values():
 p=Path(v['path']);assert p.stat().st_size==v['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==v['sha256']
owner=list(Path('apps/desktop/src-tauri/target/release/bundle/nsis').glob('*.exe'));candidate=list(Path('.local/p14-candidate').glob('*.exe'));assert len(owner)==len(candidate)==1
install=root/'installed';subprocess.run([str(owner[0].resolve()),'/S','/D='+str(install)],check=True,timeout=180);apps=[p for p in install.glob('*.exe') if 'uninstall' not in p.name.lower()];assert len(apps)==1;app=apps[0];before=hashlib.sha256(app.read_bytes()).hexdigest()
child=subprocess.Popen([str(candidate[0].resolve()),'/P','/UPDATE','/R']);time.sleep(8)
command="$all=Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId;ConvertTo-Json -Compress -InputObject @($all)";rows=json.loads(subprocess.check_output(['powershell','-NoProfile','-NonInteractive','-Command',command],text=True,encoding='utf-8'));owned={child.pid}
for _ in range(10):
 new={int(p['ProcessId']) for p in rows if int(p['ParentProcessId']) in owned};previous=len(owned);owned.update(new)
 if len(owned)==previous:break
user=ctypes.WinDLL('user32');callback=ctypes.WINFUNCTYPE(ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p);windows=[]
user.GetWindowThreadProcessId.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ulong)];user.GetWindowTextW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_int];user.GetClassNameW.argtypes=[ctypes.c_void_p,ctypes.c_wchar_p,ctypes.c_int];user.IsWindowVisible.argtypes=[ctypes.c_void_p]
def observe(hwnd,param):
 pid=ctypes.c_ulong();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
 if pid.value in owned and user.IsWindowVisible(hwnd):
  title=ctypes.create_unicode_buffer(256);cls=ctypes.create_unicode_buffer(128);user.GetWindowTextW(hwnd,title,256);user.GetClassNameW(hwnd,cls,128);windows.append({'title':title.value,'class':cls.value})
 return 1
cb=callback(observe);user.EnumWindows(cb,0)
passive={'exited':child.poll() is not None,'exit_code':child.poll(),'main_changed':hashlib.sha256(app.read_bytes()).hexdigest()!=before,'visible_owned_installer_windows':windows}
if child.poll() is None:subprocess.run(['taskkill','/PID',str(child.pid),'/T','/F'],check=True,capture_output=True);child.wait(timeout=10)
assert not passive['main_changed'],'Passive update already succeeded; investigate app launch context instead'
quiet=subprocess.run([str(candidate[0].resolve()),'/S','/UPDATE','/R'],capture_output=True,timeout=180);after=hashlib.sha256(app.read_bytes()).hexdigest()
version=subprocess.check_output(['powershell','-NoProfile','-NonInteractive','-Command',"(Get-Item -LiteralPath '"+str(app).replace("'","''")+"').VersionInfo.FileVersion"],text=True,encoding='utf-8').strip()
report={'purpose':'P14 public exact NSIS passive versus quiet update diagnosis','source_commit':'72daa1ec25f94738b4b4479aa36983a3fa41010d','status':'PASS' if quiet.returncode==0 and before!=after and version=='0.14.1' else 'FAILED','passive':passive,'quiet':{'exit_code':quiet.returncode,'main_changed':before!=after,'file_version':version},'physical_acceptance':False,'scope':'Installer-mode control only; bypasses no signing policy and does not claim full app updater/gigabyte acceptance'}
print(json.dumps(report,indent=2),flush=True);dest=Path('artifacts/p14-installer-control');dest.mkdir(parents=True,exist_ok=True);(dest/'report.json').write_text(json.dumps(report,indent=2)+'\n');assert report['status']=='PASS'
