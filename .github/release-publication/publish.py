"""Reconstruct exact preverified public deliveries and publish a review prerelease."""
import concurrent.futures
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

HERE=Path(__file__).resolve().parent
CONFIG=json.loads((HERE/'config.json').read_text())
WORK=Path(os.environ['RUNNER_TEMP'])/'anynote-review-publication'
WORK.mkdir(exist_ok=False)
TOKEN=os.environ['GITHUB_TOKEN']
REPO='kurasis/AnyNote'
RID=CONFIG['release_id']
sha=lambda p:hashlib.file_digest(Path(p).open('rb'),'sha256').hexdigest()


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,url):
        assert req.get_method() in ['GET','HEAD'],'Mutation redirect requires inspection'
        assert urllib.parse.urlsplit(url).scheme=='https','HTTPS required'
        new=super().redirect_request(req,fp,code,msg,headers,url)
        if urllib.parse.urlsplit(url).hostname!='api.github.com':
            for collection in [new.headers,new.unredirected_hdrs]:
                for key in list(collection):
                    if key.lower()=='authorization':collection.pop(key)
        return new


def request(path,method='GET',data=None,upload=False,length=None):
    if upload:
        url=path;p=urllib.parse.urlsplit(url)
        assert p.scheme=='https' and p.hostname=='uploads.github.com'
        assert p.path=='/repos/'+REPO+'/releases/'+str(RID)+'/assets'
    else:
        assert path.startswith('repos/'+REPO+'/')
        url='https://api.github.com/'+path
    headers={'Authorization':'Bearer '+TOKEN,'Accept':'application/vnd.github+json',
             'User-Agent':'AnyNote-exact-review-publication','X-GitHub-Api-Version':'2022-11-28'}
    if length is not None:
        headers.update({'Content-Type':'application/octet-stream','Content-Length':str(length)})
    elif data is not None:
        data=json.dumps(data).encode();headers['Content-Type']='application/json'
    req=urllib.request.Request(url,data=data,headers=headers,method=method)
    try:return urllib.request.build_opener(Redirect()).open(req,timeout=1200)
    except urllib.error.HTTPError as error:
        raise RuntimeError('GitHub HTTP '+str(error.code)+' during scoped '+method)from None
    except (urllib.error.URLError,TimeoutError,OSError):
        raise RuntimeError('GitHub transport incomplete; inspect remote state before retry')from None


def api(suffix,method='GET',data=None):
    with request('repos/'+REPO+'/'+suffix,method,data)as response:
        raw=response.read(4*1024**2+1);assert len(raw)<=4*1024**2
        return json.loads(raw)if raw else None


def safe(name):
    p=PurePosixPath(name)
    assert name and not p.is_absolute() and '\\'not in name and all(v not in ['', '.', '..']for v in name.split('/'))
    return name


def progress(status,**fields):
    record={'status':status,**fields}
    (WORK/'publication-progress.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record),flush=True)


progress('START',python=sys.version.split()[0],zlib=zlib.ZLIB_RUNTIME_VERSION)
assert sha(HERE/'inputs.zip')==CONFIG['inputs_zip_sha256']
with zipfile.ZipFile(HERE/'inputs.zip')as z:
    assert len(z.infolist())<2000
    for member in z.infolist():
        name=safe(member.filename);assert member.file_size<64*1024**2
        target=WORK/name;target.parent.mkdir(parents=True,exist_ok=True)
        with z.open(member)as source,target.open('xb')as dest:shutil.copyfileobj(source,dest,1024**2)
plan=json.loads((WORK/'asset-plan.json').read_text())
assert plan['source_commit']==CONFIG['source_commit'] and plan['tag']==CONFIG['tag']
release=api('releases/'+str(RID))
assert release['tag_name']==CONFIG['tag'] and release['prerelease'] is True
assert release['target_commitish']==CONFIG['source_commit']
assert release['draft'] is True,'Inspect already published state before another action'

handoff=WORK/'handoff'
jobs=[]
for role in ['main','pr-final','pr-initial','pr-revised','pr-search','pr-pretriage']:
    folder=handoff/'artifacts'/role
    receipt=json.loads((folder/'download-receipt.json').read_text())
    for row in receipt['artifacts']:jobs.append((folder,row))
assert len(jobs)==155


def download(job):
    folder,row=job;target=folder/(str(row['id'])+'.zip')
    meta=json.loads((folder/(str(row['id'])+'.json')).read_text())
    assert meta['digest']=='sha256:'+row['zip_sha256'] and meta['size_in_bytes']==row['zip_bytes']
    count=0
    with request('repos/'+REPO+'/actions/artifacts/'+str(row['id'])+'/zip')as source,target.open('xb')as dest:
        while block:=source.read(1024**2):
            count+=len(block);assert count<=row['zip_bytes'];dest.write(block)
    assert count==row['zip_bytes'] and sha(target)==row['zip_sha256']
    return row['id']


with concurrent.futures.ThreadPoolExecutor(max_workers=4)as pool:
    futures=[pool.submit(download,j)for j in jobs]
    for index,future in enumerate(concurrent.futures.as_completed(futures),1):
        identifier=future.result()
        if index%10==0 or index==len(jobs):progress('ORIGINAL_ZIPS_VERIFIED',count=index,total=len(jobs),last_id=identifier)

for role in ['main','pr-final']:
    review=handoff/('review-'+role)
    acceptance=json.loads((review/'acceptance.json').read_text())
    assert acceptance['status']=='PASS' and acceptance['mandatory_jobs']==30
    for package in acceptance['packages']:
        target=review/safe(package['path']);assert target.parent==review
        with zipfile.ZipFile(handoff/'artifacts'/role/(str(package['artifact_id'])+'.zip'))as z:
            names=[n for n in z.namelist()if n==package['path']or n.endswith('/'+package['path'])]
            assert len(names)==1 and z.getinfo(names[0]).file_size==package['bytes']
            with z.open(names[0])as source,target.open('xb')as dest:shutil.copyfileobj(source,dest,1024**2)
        assert sha(target)==package['sha256']
progress('SIX_ORIGINAL_CANDIDATES_VERIFIED')

delivery=WORK/'delivery'
delivery_manifest=json.loads((delivery/'release-manifest.json').read_text())
expected={r['path']:r for r in delivery_manifest['files']}


def destination(role,name):
    for prefix,replacement in [('source/','Source/'),('windows/','Windows/'),('pwa/','PWA/'),('api/','Server/')]:
        if name.startswith(prefix):return replacement+name.removeprefix(prefix)
    if name.startswith('evidence/'):return 'Evidence/'+role+'/'+name.removeprefix('evidence/')
    return 'Reference/'+role+'/'+name


main=json.loads((handoff/'review-main/acceptance.json').read_text())
for package in main['packages']:
    role=package['role']
    with tarfile.open(handoff/'review-main'/package['path'],'r|gz')as archive:
        for member in archive:
            assert member.isreg() and not member.pax_headers
            name='Evidence/'+role+'/candidate.json'if member.name=='candidate.json'else destination(role,safe(member.name))
            row=expected[name];assert member.size==row['bytes']
            target=delivery/safe(name);target.parent.mkdir(parents=True,exist_ok=True)
            if not target.exists():
                with archive.extractfile(member)as source,target.open('xb')as dest:shutil.copyfileobj(source,dest,1024**2)
            assert sha(target)==row['sha256']
for name,row in expected.items():
    p=delivery/safe(name);assert p.stat().st_size==row['bytes']and sha(p)==row['sha256']
assert {p.relative_to(delivery).as_posix()for p in delivery.rglob('*')if p.is_file()}==set(expected)|{'release-manifest.json','MANIFEST.sha256'}
progress('RELEASE_PAYLOAD_VERIFIED',files=len(expected)+2)

assets=WORK/'assets';assets.mkdir(exist_ok=True)
zip_records=json.loads((HERE/'delivery-zip-metadata.json').read_text())
with zipfile.ZipFile(assets/CONFIG['delivery_name'],'x')as z:
    for row in zip_records:
        name=row['filename'];relative=safe(name.split('/',1)[1]);source=delivery/relative
        info=zipfile.ZipInfo(name,tuple(row['date_time']))
        for key in ['compress_type','create_system','create_version','extract_version','reserved','flag_bits','volume','internal_attr','external_attr','file_size']:
            setattr(info,key,row[key])
        info.extra=bytes.fromhex(row['extra_hex']);info.comment=bytes.fromhex(row['comment_hex']);info._compresslevel=6
        with source.open('rb')as f,z.open(info,'w')as target:shutil.copyfileobj(f,target,1024**2)

manifest=json.loads((handoff/'manifest.json').read_text())
for row in manifest['files']:
    path=handoff/safe(row['path']);assert path.stat().st_size==row['bytes']and sha(path)==row['sha256']
with (assets/CONFIG['handoff_name']).open('xb')as raw,gzip.GzipFile(filename='',fileobj=raw,mode='wb',compresslevel=1,mtime=0)as gz:
    with tarfile.open(fileobj=gz,mode='w|',format=tarfile.USTAR_FORMAT)as archive:
        names=['manifest.json',*sorted(r['path']for r in manifest['files'])]
        for name in names:
            source=handoff/name;info=tarfile.TarInfo(name);info.size=source.stat().st_size;info.mode=0o644
            with source.open('rb')as f:archive.addfile(info,f)
shutil.copyfile(delivery/'Windows/AnyNote_0.14.0_x64-setup.exe',assets/'AnyNote_0.14.0_x64-setup.exe')
for asset in plan['assets']:
    path=assets/asset['name'];assert path.stat().st_size==asset['bytes'],asset['name']+' size mismatch'
    actual=sha(path);assert actual==asset['sha256'],asset['name']+' digest mismatch: '+actual
progress('ALL_ASSETS_MATCH_ORIGINAL_LOCAL_BYTES',assets=len(plan['assets']))


class Reader:
    def __init__(self,f,name,size):self.f=f;self.name=name;self.size=size;self.count=0;self.last=time.monotonic()
    def read(self,n):
        data=self.f.read(n);self.count+=len(data)
        if time.monotonic()-self.last>20:
            progress('UPLOADING',asset=self.name,sent_bytes=self.count,total_bytes=self.size);self.last=time.monotonic()
        return data


uploaded=[]
for asset in plan['assets']:
    existing=[a for a in api('releases/'+str(RID)+'/assets?per_page=100')if a['name']==asset['name']]
    if existing:
        assert len(existing)==1;result=existing[0]
    else:
        progress('UPLOAD_START',asset=asset['name'],bytes=asset['bytes'])
        url='https://uploads.github.com/repos/'+REPO+'/releases/'+str(RID)+'/assets?'+urllib.parse.urlencode({'name':asset['name']})
        with (assets/asset['name']).open('rb')as f,request(url,'POST',Reader(f,asset['name'],asset['bytes']),True,asset['bytes'])as response:
            raw=response.read(1024**2+1);assert len(raw)<=1024**2;result=json.loads(raw)
    assert result['state']=='uploaded'and result['size']==asset['bytes']and result['digest']=='sha256:'+asset['sha256']
    uploaded.append({'name':asset['name'],'id':result['id'],'bytes':result['size'],'sha256':asset['sha256']})
    progress('UPLOAD_SERVER_DIGEST_VERIFIED',asset=asset['name'],completed=len(uploaded),total=len(plan['assets']))
live=api('releases/'+str(RID));assert live['draft']is True and live['target_commitish']==CONFIG['source_commit']
published=api('releases/'+str(RID),'PATCH',{'draft':False,'prerelease':True,'make_latest':'false'})
assert published['draft']is False and published['prerelease']is True
receipt={'status':'PASS','release_id':RID,'tag':CONFIG['tag'],'source_commit':CONFIG['source_commit'],
         'url':published['html_url'],'assets':uploaded,'source_binaries_recompiled':False,
         'all_original_local_asset_hashes_matched':True,'production_release_allowed':False}
(WORK/'publication-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
progress('PUBLISHED_VERIFIED_PRERELEASE',url=receipt['url'],assets=len(uploaded))
