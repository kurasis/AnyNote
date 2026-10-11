#!/usr/bin/env python3
"""Independent restricted-fixture JSON/USTAR verifier using Python standard libraries."""
import hashlib,json,os,subprocess,tarfile,io
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];FIX=ROOT/'fixtures/protocol/p02/v1'
def jcs(v):
    if isinstance(v,dict):
        assert all(k.isascii() for k in v), 'Fixture subset only; not a general RFC8785 implementation'
        return '{'+','.join(jcs(k)+':'+jcs(v[k]) for k in sorted(v))+'}'
    if isinstance(v,list):return '['+','.join(map(jcs,v))+']'
    assert not isinstance(v,float)
    return json.dumps(v,ensure_ascii=False,separators=(',',':'))
def main():
    f=json.loads((FIX/'crypto.json').read_text());vectors=json.loads((FIX/'schema-vectors.json').read_text());checks=0
    for k,v in vectors.items():
        expected=b''.join(bytes.fromhex((FIX/name).read_text().strip()) for name in v['byte_blocks']);value=json.loads(expected);assert jcs(value).encode()==expected
        import base64
        assert base64.urlsafe_b64encode(hashlib.sha256(('AnyNote/p02-v1/hash/'+k+'\0').encode()+expected).digest()).decode().rstrip('=')==v['digest'];checks+=2
    for name,provider in [('rust.age','age'),('go.age','rage')]:
        # Actual OS anonymous pipe: no private identity/plaintext temporary file.
        fd,write_fd=os.pipe();os.write(write_fd,(f['objects']['kit']['export_identity']+'\n').encode());os.close(write_fd)
        try:
            result=subprocess.run([str(ROOT/'.local/p02-tools'/provider),'-d','-i',f'/dev/fd/{fd}'],pass_fds=(fd,),input=(FIX/name).read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,env={**os.environ,'LANG':'en_US.UTF-8'})
        finally:os.close(fd)
        data=result.stdout;assert len(data)<16777216
        import base64
        assert base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('=')==f['expected']['tar_sha256']
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
            members=archive.getmembers();assert members[0].name=='export-header.json' and members[-1].name=='export-footer.json'
            paths=set();end=0
            for m in members:
                assert m.isfile() and m.name not in paths and not m.linkname and not m.pax_headers;paths.add(m.name)
                assert m.uid==m.gid==m.mtime==0 and m.mode==0o600 and m.uname==m.gname==''
                assert data[m.offset:m.offset+512]==m.tobuf(format=tarfile.USTAR_FORMAT), 'Independent USTAR header mismatch'
                body=archive.extractfile(m).read();assert len(body)==m.size
                end=m.offset_data+((m.size+511)//512)*512;checks+=5
            assert data[end:]==bytes(1024), 'Exactly two authenticated end blocks'
    print(json.dumps({'status':'PASS','checks':checks,'structures':len(vectors),'scope':'INDEPENDENT_ASCII_KEY_JCS_USTAR_AND_TWO_AGE_ENGINES_NO_PRODUCT_IMPORT'}))
if __name__=='__main__':main()
