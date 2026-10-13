"""Standard-library sampled child-process working sets; public byte counts only."""
import os,sys
from pathlib import Path

def processes():
    if sys.platform == 'win32':
        import ctypes
        from ctypes import wintypes as w
        class Entry(ctypes.Structure):
            _fields_=[('size',w.DWORD),('usage',w.DWORD),('pid',w.DWORD),('heap',ctypes.c_size_t),('module',w.DWORD),('threads',w.DWORD),('parent',w.DWORD),('priority',w.LONG),('flags',w.DWORD),('name',w.WCHAR*260)]
        class Memory(ctypes.Structure):
            _fields_=[('cb',w.DWORD),('faults',w.DWORD)]+[(n,ctypes.c_size_t) for n in ['peak_ws','ws','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile']]
        kernel=ctypes.WinDLL('kernel32',use_last_error=True);psapi=ctypes.WinDLL('psapi',use_last_error=True)
        kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
        kernel.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)];kernel.Process32NextW.argtypes=kernel.Process32FirstW.argtypes
        kernel.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];kernel.OpenProcess.restype=w.HANDLE
        kernel.CloseHandle.argtypes=[w.HANDLE];psapi.GetProcessMemoryInfo.argtypes=[w.HANDLE,ctypes.POINTER(Memory),w.DWORD]
        handle=kernel.CreateToolhelp32Snapshot(2,0)
        if handle==ctypes.c_void_p(-1).value: raise OSError('Process sampling unavailable')
        entry=Entry();entry.size=ctypes.sizeof(entry);out=[]
        try:
            available=kernel.Process32FirstW(handle,ctypes.byref(entry))
            while available:
                size=0
                if entry.name.startswith('notes-'):
                    process=kernel.OpenProcess(0x1000|0x10,False,entry.pid)
                    if process:
                        try:
                            memory=Memory();memory.cb=ctypes.sizeof(memory)
                            if psapi.GetProcessMemoryInfo(process,ctypes.byref(memory),memory.cb):size=memory.ws
                        finally:kernel.CloseHandle(process)
                out.append((entry.pid,entry.parent,entry.name,size))
                available=kernel.Process32NextW(handle,ctypes.byref(entry))
        finally:kernel.CloseHandle(handle)
        return out
    out=[]
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():continue
        try:
            stat=(path/'stat').read_text().split(') ',1)[1].split();name=(path/'comm').read_text().strip()
            size=0
            if name.startswith('notes-'):
                fields=(path/'statm').read_text().split();size=int(fields[1])*os.sysconf('SC_PAGE_SIZE')
            out.append((int(path.name),int(stat[1]),name,size))
        except (OSError,ValueError,IndexError):continue
    return out

class Sampler:
    def __init__(self,parent):self.parent=parent;self.count=0;self.baseline=None;self.peak=0
    def sample(self):
        rows=processes();descendants={self.parent}
        for _ in range(16):
            found={pid for pid,parent,_,_ in rows if parent in descendants}
            if found.issubset(descendants):break
            descendants.update(found)
        values=[size for pid,_,name,size in rows if pid in descendants and name.startswith('notes-') and size>0]
        if values:
            size=sum(values);self.count+=1
            if self.baseline is None:self.baseline=size
            self.peak=max(self.peak,size)
    def report(self):
        assert self.count>0 and self.peak>0,'No native notes memory samples executed'
        return {'samples':self.count,'sample_interval_ms':250,'observed_peak_working_set_bytes':self.peak,'first_sample_working_set_bytes':self.baseline,'observed_peak_growth_bytes':max(0,self.peak-self.baseline),'scope':'actual native 1 GB transfer phase after vault initialization/unlock, includes allocator/SQLite overhead; first phase sample is baseline; sampled RSS/working set is not a hard ceiling or a physical WebView2 measurement'}
